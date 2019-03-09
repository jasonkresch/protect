# protect
A **P**latform for **Ro**bust **T**hr**e**shold **C**ryp**t**ography

## Overview

**PROTECT** provides a platform for *threshold-secure* cryptography.  It can be used to implement systems and services that tolerate multiple simultaneous faults and security breaches without loss of security, availability, or correctness.  Moreoever, the system self-heals from faults and self-restores full security following breaches.  Due to these recovery properties, **PROTECT** can be used to maintain confidential information (secret keys, bitcoin wallets, numbered bank accounts, etc.) over the long periods of time, despite inevitable data loss and data exposure events.

**PROTECT** is based on [Secret Sharing](https://en.wikipedia.org/wiki/Secret_sharing), and leverages the algebraic relationships that exist between the shares to compute evaluate functions on these shares, which can include key generation, key derivation, public key decryption, and signature generation.  Several client utilities are included in the protect project to show how to create a distributed certificate authority whose RSA private key exists in no location, and another, showing how an Elliptic Curve private key can decrypt ciphertexts again without the key existing in any location.  Thus one can engineer secure cryptographic services *having no single points of failure nor any single point of compromise*.


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
