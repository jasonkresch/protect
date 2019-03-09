# protect
A **P**latform for **Ro**bust **T**hr**e**shold **C**ryp**t**ography

## Overview

*PROTECT* is a open source platform for *threshold-secure* cryptography.  It can be used to implement systems and services that tolerate multiple simultaneous faults and security breaches without loss of security, availability, or correctness.  Moreoever, PROTECT self-heals  from destruction events and self-restores full security following security breaches.  Thus PROTECT can be used to maintain secrets over the long term, with minimal risk of loss or exposure.

It can be used to implement services that need to function with no single point of failure and no single point of compromise.

### Supported Secret Management Operations
* Secret Lifecycle
** Distributed Key Generation
** Proactive Refresh
** Share Recovery
* Managmenet
** Store Share
** Read Share
** Delete Share
** Enable Share
** Disable Share

### Currently Supported Cryptographic Operations
* Elliptic Curves
** Pseudorandom Functions
** Oblivious Pseudorandom Functions
** ECIES Encryption
** Elliptic Curve Diffie Hellman Key Agreement
* RSA
** Signatures
** Blind Signatures
** Decryption

### Operations Coming Soon
* Diffie Hellman
** ElGamal Encryption
** Diffie-Hellman Key Agreement
* Bilinear Pairings
** Boneh–Lynn–Shacham Signatures

### Planned Future Enhancement
* Schnorr Signatures
* ECDSA Signatures
* Share Conversion
* Share Multiplication
* Multiparty Computation
** Threshold AES
* RSA
** Distributed Key Generation
** Proactive Refresh
** Share Recovery
* Post-Quantum Cryptography



It implements distributed protocols for generating, managing and using shared secrets to perform cryptographic operations. Because the secrets can be used without having to reasseble the shares, this provides threshold-security and a robust system without single points of failure or compromise.  Further, PROTECT implements without having to reasseble and further, provides automatic self-healing 


## System Confiuration

1. Downloading:
[![Alt text](https://img.youtube.com/vi/9sDgPOUpADw/0.jpg)](https://www.youtube.com/watch?v=9sDgPOUpADw)

2. Buidling and Installing
[![Alt text](https://img.youtube.com/vi/Cz9VV0FzW10/0.jpg)](https://www.youtube.com/watch?v=Cz9VV0FzW10)

3. Server Configuration
[![Alt text](https://img.youtube.com/vi/BHM17XE6ZhQ/0.jpg)](https://www.youtube.com/watch?v=BHM17XE6ZhQ)

4. Running Servers
[![Alt text](https://img.youtube.com/vi/H4rX8gtqjrI/0.jpg)](https://www.youtube.com/watch?v=H4rX8gtqjrI)

5. Client Configuration
[![Alt text](https://img.youtube.com/vi/DXvrh1b8GH4/0.jpg)](https://www.youtube.com/watch?v=DXvrh1b8GH4)

6. Managing Secrets
[![Alt text](https://img.youtube.com/vi/ZMjMlC52MJc/0.jpg)](https://www.youtube.com/watch?v=ZMjMlC52MJc)

7. Cryptographic Operations
[![Alt text](https://img.youtube.com/vi/hVjxZmUPwlU/0.jpg)](https://www.youtube.com/watch?v=hVjxZmUPwlU)


## References


This project implements the Proactive Secret Sharing (PROSS) protocol, first described in 1995 by Amir Herzberg, Stanislaw Jarecki, Hugo Krawczyk, and Moti Yung in their paper ["Proactive Secret Sharing Or: How to Cope with Perpetual Leakage"](https://pdfs.semanticscholar.org/d367/55ccc7902e3e09db5c82897401ab0877df3d.pdf).

Additionally, this project implements the Distributed Key Generation (DKG) protocol, first described in 1999 by Rosario Gennaro, Stanislaw Jarecki, Hugo Krawczyk, and Tal Rabin in their 1999 paper ["Secure Distributed Key Generation for Discrete-Log Based Cryptosystems"](https://groups.csail.mit.edu/cis/pubs/stasio/vss.ps.gz).

Both of these protocols depend on an atomic broadcast channel. In the real world of asynchronrouns networks and distributed systems the idealization of an atomic broadcast channel must be built on top of a distributed, byzantine-fault-tolerant, consensus system.  Therefore network communication among the component servers of the PROSS and DKG systems uses [Byzantine Fault Tolerant (BFT) State Machine Replication (SMR)](http://repositorio.ul.pt/bitstream/10451/14170/1/TR-2013-07.pdf) based on the [BFT-SMaRt library](https://github.com/bft-smart/library).

## Deploying

TODO: Write deployment instructions

## Operations

TODO: Provide examples of performing various supported operations


## Contributing
Contributions welcome! See [Contributing](CONTRIBUTING.md) for details.
