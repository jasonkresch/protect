# protect
A **P**latform for **Ro**bust **T**hr**e**shold **C**ryp**t**ography

## Overview

PROTECT provides a platform for implementing threshold-secure applications and services.  It implements distributed protocols for generating, managing and using shared secrets to perform cryptographic operations. Because the secrets can be used without having to reasseble the shares, this provides threshold-security and a robust system without single points of failure or compromise.  Further, PROTECT implements without having to reasseble and further, provides automatic self-healing 


PROTECT is an open source (MIT Licensed) platform for threshold-secure operations
Tolerates (n/3) – (n/2) Byzantine faults
Operates over eventually synchronous networks
Self-heals and self-secures after faults and breaches

Supported operations:
(O)PRF, ECIES, BLS, RSA (Blind)Sign/Decrypt
Generate, Store, Read, Delete, Enable, Disable

Future enhancement goals:
Share conversion, Schnorr signatures, ECDSA
Share multiplication, MPC, Threshold AES
RSA (DKG/Refresh/Recover)
Post-Quantum Cryptography



This project implements the Proactive Secret Sharing (PROSS) protocol, first described in 1995 by Amir Herzberg, Stanislaw Jarecki, Hugo Krawczyk, and Moti Yung in their paper ["Proactive Secret Sharing Or: How to Cope with Perpetual Leakage"](https://pdfs.semanticscholar.org/d367/55ccc7902e3e09db5c82897401ab0877df3d.pdf).

Additionally, this project implements the Distributed Key Generation (DKG) protocol, first described in 1999 by Rosario Gennaro, Stanislaw Jarecki, Hugo Krawczyk, and Tal Rabin in their 1999 paper ["Secure Distributed Key Generation for Discrete-Log Based Cryptosystems"](https://groups.csail.mit.edu/cis/pubs/stasio/vss.ps.gz).

Both of these protocols depend on an atomic broadcast channel. In the real world of asynchronrouns networks and distributed systems the idealization of an atomic broadcast channel must be built on top of a distributed, byzantine-fault-tolerant, consensus system.  Therefore network communication among the component servers of the PROSS and DKG systems uses [Byzantine Fault Tolerant (BFT) State Machine Replication (SMR)](http://repositorio.ul.pt/bitstream/10451/14170/1/TR-2013-07.pdf) based on the [BFT-SMaRt library](https://github.com/bft-smart/library).

## Deploying

TODO: Write deployment instructions

## Operations

TODO: Provide examples of performing various supported operations


## Contributing
Contributions welcome! See [Contributing](CONTRIBUTING.md) for details.
