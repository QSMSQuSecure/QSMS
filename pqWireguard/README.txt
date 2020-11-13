At the moment PQ-WireGuard only supports Linux.
Note that PQ-WireGuard is optimized with AVX2 instructions. Therefore CPUs that do not provide this instruction set are not supported, which are:
    Intel CPUs before Q2 2013 (Haswell)
    AMD CPUs before Q2 2015 (Excavator)
    (See https://en.wikipedia.org/wiki/Advanced_Vector_Extensions#CPUs_with_AVX2 for more info)
Running PQ-WireGuard on unsupported CPUs may cause the kernel to crash, and the following error message can be expected: illegal hardware instruction (core dumped)

1. To compile and install PQ-WireGuard:

    sudo apt-get install libelf-dev linux-headers-$(uname -r) build-essential pkg-config
    cd libmnl-1.0.4
    ./configure
    make
    sudo make install
    cd .. && cd WireGuard/src
    make all
    sudo make install

2. To create a PQ-WireGuard VPN network:

    cd server && ./run.sh
    Create two more VMs and repeat step 1 on each machine.
    On the first VM: cd client-1 && ./run.sh
    On the second VM: cd client-2 && ./run.sh

    See setup_vpn_config.sh to see how this network was configured.

3. To run Tamarin symbolic model of PQ-WireGuard:
    1. Install Tamarin: https://tamarin-prover.github.io/manual/book/002_installation.html
    2. And then run: tamarin-prover --prove pq_wireguard.spthy
    3. Due to memory requirements, it is advised to prove each group of lemmas (or even each lemma)
        separately with the command: tamarin_prover --prove=$GROUP_PREFIX pq_wireguard.spthy

4. To run the Python2 script for choosing parameters of Dagger:
    1. Install python2 packages numpy, matplotlib (and perhaps some backports packages, depending on the system)
    2. and then run: cd param-select && python2 select_param.py
