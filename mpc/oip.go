package main

import (
	"fmt"
	"sync"

	"github.com/ldsec/lattigo/v2/bfv"
)

const DIMENSION int = 1 << 12

func SetupParams() bfv.Parameters {
	lit := bfv.PN12QP109
	params, err := bfv.NewParametersFromLiteral(lit)
	if err != nil {
		panic(err)
	}
	return params
}

type OIP struct {
	me      int // my index
	parties int // number of parties

	// pipes
	conn [][]Connection

	// public keys of other parties
	recv *Receiver
	send []*Sender
}

func (oip *OIP) ConnSend(him int) Connection {
	if him > oip.me {
		return oip.conn[0][him]
	} else {
		return oip.conn[1][him]
	}
}

func (oip *OIP) ConnRecv(him int) Connection {
	if him > oip.me {
		return oip.conn[1][him]
	} else {
		return oip.conn[0][him]
	}
}

func NewOIP(
	conn [][]Connection,
	me,
	parties int,
) (*OIP, error) {
	oip := &OIP{}
	oip.me = me
	oip.parties = parties

	// setup receivers
	params := SetupParams()
	oip.recv = NewReceiver(params)
	oip.conn = conn

	// send public key to every other party
	func() {
		fmt.Println("Broadcast own public key")

		setup := MsgSetup{
			Pk:  oip.recv.pk,
			Rlk: oip.recv.rlk,
		}

		// send to each party
		for party := 0; party < oip.parties; party++ {
			if party == me {
				continue
			}

			// wait for message
			go func(party int, setup *MsgSetup) {
				c := oip.conn[0][party]
				if err := c.WriteMsgSetup(setup); err != nil {
					panic(err)
				}
			}(party, &setup)
		}
	}()

	oip.send = make([]*Sender, oip.parties)

	// receive public keys and setup senders
	var wg sync.WaitGroup
	defer wg.Wait()
	func() {
		fmt.Println("Receieve public keys")

		// receieve from each party
		for party := 0; party < oip.parties; party++ {
			if party == me {
				continue
			}

			wg.Add(1)
			go func(party int) {
				defer wg.Done()
				c := oip.conn[0][party]
				msg, err := c.ReadMsgSetup()
				if err != nil {
					panic(err)
				}
				oip.send[party] = NewSender(params, msg)
			}(party)
		}
	}()

	return oip, nil
}

func (oip *OIP) send_oip(
	conn Connection,
	sender *Sender,
	share_mx *sync.Mutex,
	share []uint64,
	mapping [][]int,
	b []uint64,
	v []uint64,
) {
	size := len(share)
	blocks := (size + DIMENSION - 1) / DIMENSION
	branches := len(mapping)
	pad_size := blocks * DIMENSION

	// receieve message from receiever
	msg1, err := conn.ReadMsgReceiver()
	if err != nil {
		panic(err)
	}

	x := random(pad_size)

	// add random masks (parallel)
	send := make(chan chan *bfv.Ciphertext, blocks)
	for block := 0; block < blocks; block++ {
		c := make(chan *bfv.Ciphertext, 1)
		go func(block int, res chan *bfv.Ciphertext) {
			//
			s := block * DIMENSION
			e := (block + 1) * DIMENSION

			// create 0 ct
			ct := bfv.NewCiphertext(oip.recv.params, DIMENSION)

			// add random mask
			pt_mask := bfv.NewPlaintext(oip.recv.params)
			sender.encoder.EncodeUint(x[s:e], pt_mask)
			sender.evaluator.Add(ct, pt_mask, ct)

			// add branches
			var wg sync.WaitGroup
			var mx sync.Mutex
			for branch := 0; branch < branches; branch++ {
				wg.Add(1)
				go func(branch int) {
					defer wg.Done()
					// start and end of block
					l := DIMENSION
					t := make([]uint64, DIMENSION)
					if e > size {
						l = size - s
					}

					// apply permutation
					m := mapping[branch]
					for j := 0; j < l; j++ {
						t[j] = v[m[j+s]]
					}

					// multiply choice by message
					ct_tmp := bfv.NewCiphertext(oip.recv.params, DIMENSION)
					pt_mul := bfv.NewPlaintextMul(oip.recv.params)
					sender.encoder.EncodeUintMul(t, pt_mul)
					sender.evaluator.Mul(msg1.Cts[branch], pt_mul, ct_tmp)

					mx.Lock()
					sender.evaluator.Add(ct, ct_tmp, ct)
					mx.Unlock()
				}(branch)
			}
			wg.Wait()
			fmt.Println("Sender, block processed")
			res <- ct
		}(block, c)
		send <- c
	}

	// subtract mask from own share
	share_mx.Lock()
	for i := 0; i < len(share); i++ {
		share[i] = sub(share[i], x[i])
	}
	share_mx.Unlock()

	// send messages from workers
	for i := 0; i < blocks; i++ {
		c := <-send
		conn.WriteCT(<-c)
	}
}

func (oip *OIP) recv_oip(
	conn Connection,
	share_mx *sync.Mutex,
	share []uint64,
	b []uint64,
) {
	size := len(share)
	blocks := (size + DIMENSION - 1) / DIMENSION
	pad_size := blocks * DIMENSION

	// send first message
	msg1 := oip.recv.NewSelection(b)
	err := conn.WriteMsgReceiver(msg1)
	if err != nil {
		panic(err)
	}

	// decryption result slice
	var res_mx sync.Mutex
	res := make([]uint64, pad_size)

	// decrypt message in parallel
	var wg sync.WaitGroup
	for i := 0; i < blocks; i++ {
		// get next ciphertext
		ct, err := conn.ReadCT()
		if err != nil {
			panic(err)
		}
		fmt.Println("Got OIP block.")

		//
		wg.Add(1)
		go func(i int, ct *bfv.Ciphertext) {
			defer wg.Done()

			// start and end of block
			s := i * DIMENSION
			e := (i + 1) * DIMENSION

			// descrypt block
			pt_new := bfv.NewPlaintext(oip.recv.params)
			oip.recv.decryptor.Decrypt(ct, pt_new)
			res_mx.Lock()
			oip.recv.encoder.DecodeUint(pt_new, res[s:e])
			res_mx.Unlock()
			fmt.Println("Decrypted OIP block.")
		}(i, ct)
	}

	// wait for work to complete
	wg.Wait()

	// accumulate into share
	share_mx.Lock()
	for i := 0; i < size; i++ {
		share[i] = add(share[i], res[i])
	}
	share_mx.Unlock()
}

func (oip *OIP) OIPMapping(mapping [][]int, b []uint64, v []uint64) ([]uint64, error) {
	// debug
	// b = []uint64{1, 0}
	// v = []uint64{1, 2, 3, 4, 5, 6}
	// fmt.Println("OIPMapping, v:", v, "b:", b)

	if len(mapping) != len(b) {
		fmt.Println(
			"len(mapping) =", len(mapping),
			"len(mapping[0]) =", len(mapping[0]),
			"len(b) =", len(b),
			"len(v) =", len(v),
		)
		panic("invalid dimension")
	}

	size := len(mapping[0])
	branches := len(mapping)

	var wg sync.WaitGroup
	var share_mx sync.Mutex // lock protecting the share
	share := make([]uint64, size)

	// calculate local cross terms
	wg.Add(1)
	go func() {
		share_mx.Lock()
		for branch := 0; branch < branches; branch++ {
			m := mapping[branch]
			for i := 0; i < size; i++ {
				h := mul(b[branch], v[m[i]])
				share[i] = add(share[i], h)
			}
		}
		share_mx.Unlock()
		wg.Done()
	}()

	// act as receiever
	for party := 0; party < oip.parties; party++ {
		if party == oip.me {
			continue
		}
		wg.Add(1)
		go func(party int) {
			oip.recv_oip(
				oip.ConnRecv(party),
				&share_mx,
				share,
				b,
			)
			wg.Done()
		}(party)
	}

	// act as sender
	for party := 0; party < oip.parties; party++ {
		if party == oip.me {
			continue
		}
		wg.Add(1)
		go func(party int) {
			oip.send_oip(
				oip.ConnSend(party),
				oip.send[party],
				&share_mx,
				share,
				mapping,
				b,
				v,
			)
			wg.Done()
		}(party)
	}

	// wait for senders/receivers to finish

	wg.Wait()

	return share, nil
}

func (oip *OIP) TryOIPMapping(mapping [][]int, b []uint64, v []uint64) []uint64 {
	res, err := oip.OIPMapping(mapping, b, v)
	if err != nil {
		panic(err)
	}
	return res
}
