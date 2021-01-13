1. To compile and install PQ-WireGuard:
    Same as the origianl WireGuard (https://www.wireguard.com/compilation)
    One simply needs to use the source code of PQ-WireGuard instead of cloning from the original
    git repo at Step 2.

    At the moment PQ-WireGuard only supports Linux. Windows and MacOS are not supported.

2. To create a PQ-WireGuard VPN network: see setup_vpn_config.sh as an example
    Note that PQ-WireGuard is optimized with AVX2 instructions. Therefore CPUs that do not provide
    this instruction set are not supported, which are:
        Intel CPUs before Q2 2013 (Haswell)
        AMD CPUs before Q2 2015 (Excavator)
    (See https://en.wikipedia.org/wiki/Advanced_Vector_Extensions#CPUs_with_AVX2 for more info)

    Running PQ-WireGuard on unsupported CPUs may cause the kernel to crash, and the following error
    message can be expected: illegal hardware instruction (core dumped)

3. To run Tamarin symbolic model of PQ-WireGuard:
    1. Install Tamarin: https://tamarin-prover.github.io/manual/book/002_installation.html
    2. And then run: tamarin_prover --prove pq_wireguard.spthy
    3. Due to memory requirements, it is advised to prove each group of lemmas (or even each lemma)
        separately with the command: tamarin_prover --prove=$GROUP_PREFIX pq_wireguard.spthy

4. To run the Python2 script for choosing parameters of Dagger:
    1. Install python2 packages numpy, matplotlib (and perhaps some backports packages, depending on the system)
    2. and then run: cd param-select && python2 select_param.py
