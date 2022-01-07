# Requirements

- Python3
- Go (version 1.17)
- [MP-SPDZ (included)](https://github.com/data61/MP-SPDZ)
- [pwntools (for auto benchmarking)](https://github.com/Gallopsled/pwntools)

# Building

Start by building `MP-SPDZ` including `semi-party.x` (semi-honest MASCOT). See [MP-SPDZ](https://github.com/data61/MP-SPDZ) documentation.

Our branching MPC implementation compiles a branching circuit into a `MP-SPDZ` circuit (python program) and a `runner` (`mpc/runner.go`) which is a Go program interacting
with `MP-SPDZ` and executing the branching functionality (with the help of Lattigo).
In short:

1. A branching circuit is generated and compiled using `circuit.py`.
2. The Go program (`bmpc`) is compiled.
3. The `MP-SPDZ` circuit is compiled.

See `circ.sh` for the process.
To run the computation, the Go program is run by supplying the `MP-SPDZ` arguments to it which it then uses to start and wrap `MP-SPDZ` in turn.

# Benchmarking

To simplify the benchmarking progress, we construct a python script (`runner.py`) which does all this work automatically (over localhost).
The interface is as follows:

```
python3 ./runner.py <players> <branches> [naive/bmpc]
```

In other words, it takes the number of players, the number of branches and whether to benchmark the naive solution (using `MP-SPDZ`) or the proposed branching MPC technique.
The script returns the outputs of all sub-commands (note that compiling the `MP-SPDZ` circuits takes significantly longer than the benchmark itself).
At the end it returns the wall-clock time in seconds of the distributed computation only.

Examples (3 players, 32 branches, naive and branching MPC respectively):

```
python3 ./runner.py 3 32 naive
```

```
python3 ./runner.py 3 32 bmpc
```

This script relies on `pwntools`.
