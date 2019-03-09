# protect
A **P**latform for **Ro**bust **T**hr**e**shold **C**ryp**t**ography

## Overview

**PROTECT** provides a platform for *threshold-secure* cryptography.  It can be used to implement systems and services that tolerate multiple simultaneous faults and security breaches without loss of security, availability, or correctness.  Moreoever, the system self-heals from faults and self-restores full security following breaches.  Due to these recovery properties, **PROTECT** can be used to maintain confidential information (secret keys, bitcoin wallets, numbered bank accounts, etc.) over the long periods of time, despite inevitable data loss and data exposure events.

**PROTECT** is based on [Secret Sharing](https://en.wikipedia.org/wiki/Secret_sharing), and leverages the algebraic relationships that exist between the shares to compute evaluate functions on these shares, which can include key generation, key derivation, public key decryption, and signature generation.  Several client utilities are included in the protect project to show how to create a distributed certificate authority whose RSA private key exists in no location, and another, showing how an Elliptic Curve private key can decrypt ciphertexts again without the key existing in any location.  Thus one can engineer secure cryptographic services *having no single points of failure nor any single point of compromise*.

## Functionality

 * Secret Lifecycle Operations
  * Distributed Key Generation
  * Proactive Refresh
  * Share Recovery
 * Share Management
  * Store Share
  * Read Share
  * Delete Share
  * Enable Share
  * Disable Share

* Cryptographic Operations (Currently Supported)
 * Elliptic Curves
  * Pseudorandom Functions
  * Oblivious Pseudorandom Functions
  * ECIES Encryption
  * Elliptic Curve Diffie Hellman Key Agreement
 * RSA
  * Signatures Generation
  * Blinded Signature Generation
  * Decryption
  
* Cryptographic Operations (Coming Soon)
 * Diffie Hellman
  * ElGamal Encryption
  * Diffie-Hellman Key Agreement
 * Bilinear Pairings
  * Boneh–Lynn–Shacham Signatures
  
* Cryptographic Operations (Future Enhancement / Research)
 * Schnorr Signatures
 * ECDSA Signatures
 * Share Conversion
  * Partially Oblivious Pseudorandom Functions
 * Share Multiplication
  * Multiparty Computation
   * Threshold AES
 * RSA
  * Distributed Key Generation
  * Proactive Refresh
  * Share Recovery
 * Post-Quantum Cryptography



It implements distributed protocols for generating, managing and using shared secrets to perform cryptographic operations. Because the secrets can be used without having to reasseble the shares, this provides threshold-security and a robust system without single points of failure or compromise.  Further, PROTECT implements without having to reasseble and further, provides automatic self-healing 




## Deployment

### Download

[![Alt text](https://img.youtube.com/vi/9sDgPOUpADw/0.jpg)](https://www.youtube.com/watch?v=9sDgPOUpADw)

### Build

[![Alt text](https://img.youtube.com/vi/Cz9VV0FzW10/0.jpg)](https://www.youtube.com/watch?v=Cz9VV0FzW10)

#### Prerequisites

**PROTECT** is written in Java but also includes some examples that use python.  On a fresh Ubuntu 18.04 system the following packages are required in order to build and launch the product.

```bash
$ sudo apt-get-update
$ sudo apt-get install openjdk-8-jdk-headless
$ sudo apt install maven
$ sudo apt install python
```

#### Compiling

Once the above prerequisites are installed PROTECT may be built by invoking the `build.sh` script.

```bash
$ git clone https://github.com/jasonkresch/protect.git
$ cd protect
$ ./build.sh
```
The end result of the build script is a self-contained jar file: `pross-server/target/pross-server-1.0-SNAPSHOT-shaded.jar`

### Configuration

#### Keys and Certificates

Pre-instaled, can skip this step if just testing, but any real deployment ***MUST*** complete this step, to create new certificates for each client and server.  Note: security of client CA certificate not important, servers use direct public key matching.  However, most browsers require the server to present the client CA certificate to prompt the user to provide one. This is not an issue for command line interaction via cURL.

#### Servers

[![Alt text](https://img.youtube.com/vi/BHM17XE6ZhQ/0.jpg)](https://www.youtube.com/watch?v=BHM17XE6ZhQ)

Show sample configuration file.
Describe optional and required fields.
Servers beyond the num servers are ignored.
Only need to change n, and set the sever IP addresses.

#### Client Access Controls

[![Alt text](https://img.youtube.com/vi/DXvrh1b8GH4/0.jpg)](https://www.youtube.com/watch?v=DXvrh1b8GH4)

Supports fine-grained user access conrols.
Uses client-side certificate authentication over TLS
Debug authentication by going to (show URL of id check page).
Describe each permission, meaning.

### Launching Servers

[![Alt text](https://img.youtube.com/vi/H4rX8gtqjrI/0.jpg)](https://www.youtube.com/watch?v=H4rX8gtqjrI)

Unqique server ID, all need to start for service to begin.

## Operations

### Interacting with System

Servers listen over HTTPS, on ports 8081 - 808n where n is number of servers.  Each server id.

#### Browser Interaction

Exploring system, servers, secrets, shares. (With read permission)
Configuring CA certificates (avoid SSL error).
Note: each server uses its own CA to issue its certificates.  These may be generated individually at each sever, then collected and distributed to all.  CA itself not checked, only used for client browsers. Servers' use direct Public key matching.

#### Command Line Interction

Initiating a DKG
Getting share info
Deleting a share
Performing Exponentiation (Getting json)
Performing signature generation (getting json)

### Secret Management

#### Generating a random secret

#### Storing a specific secret

#### Storing an RSA Private Key

#### Reading a stored secret

### Cryptograpic Operations

#### ECIES Decryption

#### Certificate Issuance



3. Server Configuration




6. Managing Secrets
[![Alt text](https://img.youtube.com/vi/ZMjMlC52MJc/0.jpg)](https://www.youtube.com/watch?v=ZMjMlC52MJc)

7. Cryptographic Operations
[![Alt text](https://img.youtube.com/vi/hVjxZmUPwlU/0.jpg)](https://www.youtube.com/watch?v=hVjxZmUPwlU)

## System Architecture

Describe system architecture
How Shareholders are connected, how they communicate
Link to Tunable Secrity eprint paper.


## References


This project implements the Proactive Secret Sharing (PROSS) protocol, first described in 1995 by Amir Herzberg, Stanislaw Jarecki, Hugo Krawczyk, and Moti Yung in their paper ["Proactive Secret Sharing Or: How to Cope with Perpetual Leakage"](https://pdfs.semanticscholar.org/d367/55ccc7902e3e09db5c82897401ab0877df3d.pdf).

Additionally, this project implements the Distributed Key Generation (DKG) protocol, first described in 1999 by Rosario Gennaro, Stanislaw Jarecki, Hugo Krawczyk, and Tal Rabin in their 1999 paper ["Secure Distributed Key Generation for Discrete-Log Based Cryptosystems"](https://groups.csail.mit.edu/cis/pubs/stasio/vss.ps.gz).

Both of these protocols depend on an atomic broadcast channel. In the real world of asynchronrouns networks and distributed systems the idealization of an atomic broadcast channel must be built on top of a distributed, byzantine-fault-tolerant, consensus system.  Therefore network communication among the component servers of the PROSS and DKG systems uses [Byzantine Fault Tolerant (BFT) State Machine Replication (SMR)](http://repositorio.ul.pt/bitstream/10451/14170/1/TR-2013-07.pdf) based on the [BFT-SMaRt library](https://github.com/bft-smart/library).

More references:
- Victor Shoup's Practical Threshold RSA Signatures
- BLS Signatures
- Ellipc Curve Pairing
- Blind Signatures (Chaum)
- Other references from NIST paper


## Contributing
Contributions welcome! See [Contributing](CONTRIBUTING.md) for details.
