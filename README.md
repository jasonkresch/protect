# protect
A **P**latform for **Ro**bust **T**hr**e**shold **C**ryp**t**ography

## Overview

***PROTECT*** provides a platform for [*threshold-secure* cryptography](https://en.wikipedia.org/wiki/Threshold_cryptosystem).  It can be used to implement systems and services that tolerate multiple simultaneous faults and security breaches without loss of privacy, availability, or correctness.  Further, the system self-heals from faults and self-recovers from breaches. This restorative capability enables **PROTECT** to maintain confidential elements (e.g., secret keys, private keys, bitcoin wallets, numbered bank accounts) durably over long periods, even if many components suffer data loss or data exposure events in that time.

***PROTECT*** leverages mathematical relationships that exist between shares in a [secret sharing scheme](https://en.wikipedia.org/wiki/Secret_sharing) to perform secure and distributed function evaluations on the secret represented by those shares. These functions include [distributed key generation](https://en.wikipedia.org/wiki/Distributed_key_generation), [share refresh](https://en.wikipedia.org/wiki/Proactive_secret_sharing), [share recovery](https://en.wikipedia.org/wiki/Proactive_secret_sharing#Motivation), [key derivation](https://en.wikipedia.org/wiki/Key_derivation_function), [public key decryption](https://en.wikipedia.org/wiki/Public-key_cryptography), and [signature generation](https://en.wikipedia.org/wiki/Digital_signature).

***PROTECT*** includes a few example clients demonstrating threshold-secure applications. These examples include:
* A distributed Certificate Authority whose private *signing key* is not held at any location
* A threshold-secure decryption service whose private *decryption key* never exists in any location
* A secret storage and retrieval client allowing the secure maintenance of arbitrary *secret values*

With the techniques implemented by ***PROTECT*** one can build secure cryptographic services *having neither any single point of failure nor any single point of compromise*.

### Functionality

The following section describes all of the funtionality ***PROTECT***.

### Secret Maintenance

The following actions are performed by servers, although the distributed key generation is initiated by a user.  Proactive Refresh and Share Recovery both occur on a scheduled periodic basis for all existing established secrets.

* **Distributed Key Generation** - Generates of shares of a random value, which is never known to anyone
* **Proactive Refresh** - Regenerates new shares for an existing secret, eliminating utility of old shares (which might have been exposed)
* **Share Recovery** - Rebuilding a lost or destroyed share without having to restore the secret or expose any share
  
### Share Management

The following are supported user actions related to the management of shares.  Note that ***PROTECT*** implements fine-grained access controls, permitting different users to be authorized to perform different functions or operations for different secrets.

* **Store Share** - Stores a specified share to enable reliably maintenance of a specific secret
* **Read Share** - Reads a share to enable determination of a secret's value
* **Delete Share** - Deletes a share to allow destruction of a secret
* **Recover Share** - Initiates an immediate share recovery of a deleted share
* **Disable Share** - Temporarily disables a share for usage
* **Enable Share** - Enables a previously disabled share for usage

### Cryptographic Operations

***PROTECT*** supports the following cryptographic functions out-of-the box today:

#### Elliptic Curves
* **Pseudorandom Functions** (PRF) - May be used to derive random looking output deterministically (for PRNGs, or KDFs)
* **Oblivious Pseudorandom Functions** - The same as a PRF but [blinded](https://en.wikipedia.org/wiki/Pseudorandom_function_family#Oblivious_pseudorandom_functions) so as to hide the input (for password hardening, OPAQUE, oblivious KDF)
* **ECIES Encryption** - The EC version of [Integrated Encryption Scheme](https://en.wikipedia.org/wiki/Integrated_Encryption_Scheme) which is based on [ElGamal](https://en.wikipedia.org/wiki/ElGamal_encryption) encryption
* **Elliptic Curve Diffie Hellman Key Agreement** (ECDH) - [ECDH](https://en.wikipedia.org/wiki/Elliptic-curve_Diffie%E2%80%93Hellman) is a Key Agreement Scheme commonly used in [TLS handshakes](https://en.wikipedia.org/wiki/Transport_Layer_Security)

#### RSA
* **Signature Generation** - Threshold signature scheme for [RSA](https://en.wikipedia.org/wiki/RSA_(cryptosystem)) based on Victor Shoup's [Practical Threshold Signatures](https://www.shoup.net/papers/thsig.pdf)
* **Blinded Signature Generation** - The same as above but [blinded](https://en.wikipedia.org/wiki/Blind_signature#Blind_RSA_signatures) from the signer.
* **Decryption** - Decryption of a ciphertext encrypted under an RSA public key. (supported but ***not recommended***, see note below)

### Roadmap Items

Very shortly support will be added to ***PROTECT*** for the following operations:

#### Diffie Hellman over Prime Groups
* Pseudorandom Functions
* Oblivious Pseudorandom Functions
* ElGamal Encryption
* Diffie-Hellman Key Agreement

#### Bilinear Pairing of Elliptic Curves
* [Generic Elliptic Curve Pairing Operation](https://en.wikipedia.org/wiki/Pairing-based_cryptography)
* [Boneh–Lynn–Shacham Signatures](https://en.wikipedia.org/wiki/Boneh%E2%80%93Lynn%E2%80%93Shacham)
* Partially Oblivious Pseudorandom Functions - As in the [Pythia PRF Service](https://eprint.iacr.org/2015/644)


## Deploying PROTECT

Protect is easy to deploy, and can get up and running in as few as three commands:

```bash
$ git clone https://github.com/jasonkresch/protect.git
$ cd protect && ./build.sh
$ cd bin && ./start-all-servers.sh 5
```
However this will launch protect using default configuration parameters, with default (***not secure***) keys, and running all instances on a single machine (***not reliable***).  The following subsections provide details on how to deploy ***PROTECT*** in a secure in reliable manner.

### Downloading PROTECT

There are two options for downloading protect as a ZIP file and using `git`.

#### Checking out via git

***PROTECT*** may be checked out using the `git` command.  This is recommended if one wants to make changes to the code base.

Github provides two URLs for checking out the project, one via HTTPS and the other via SSH. If you intend to authenticate to Github using ssh keys, you should use the SSH method.  Otherwise the HTTPS method can be used.

**Video demonstration of dowloading PROTECT using git:**

[![Alt text](https://img.youtube.com/vi/9sDgPOUpADw/0.jpg)](https://www.youtube.com/watch?v=9sDgPOUpADw)

##### Checking out via HTTPS

Checking out PROTECT via HTTPS can be accomplished with the following command:

`$ git clone https://github.com/jasonkresch/protect.git`

##### Checking out via SSH

Checking out PROTECT via HTTPS can be accomplished with the following command:

`$ git clone git@github.com:jasonkresch/protect.git`

### Downloading ZIP file

One can download ***PROTECT*** clicking the green "Clone or download" button at the top-right of this page, and then clicking the link labeled "Download ZIP" or by clicking this following link:

https://github.com/jasonkresch/protect/archive/master.zip

Note that this option requires extracting the ZIP file using an unzip utility or archive manager.

### Building

Once downloaded the entire project can be compiled into a self-contained jar by running the "build.sh" script contained in the base directory of the protect project. Details are included in the following subsections.

#### Dependencies

**PROTECT** is written in Java 1.8 but also includes some examples in python.  It uses `maven` to for dependency management and for building.  On a fresh Ubuntu install the following packages may need to be installed in order to compile and launch ***PROTECT***.

```bash
$ sudo apt-get-update
$ sudo apt-get install openjdk-8-jdk-headless
$ sudo apt install curl
$ sudo apt install maven
$ sudo apt install python
```

#### Compiling

Once the above prerequisites are installed PROTECT may be built by invoking the `build.sh` script.

**Video demonstration of compiling PROTECT into a jar:**

[![Alt text](https://img.youtube.com/vi/Cz9VV0FzW10/0.jpg)](https://www.youtube.com/watch?v=Cz9VV0FzW10)

```bash
$ git clone https://github.com/jasonkresch/protect.git
$ cd protect
$ ./build.sh
```
The end result of the build script is a self-contained jar file: `pross-server/target/pross-server-1.0-SNAPSHOT-shaded.jar`

This jar file contains all client and server functionality.

### Configuration

The following subsections detail how to configure ***PROTECT*** to run in a secure way.

#### Keys and Certificates

For ease of getting started, ***PROTECT*** comes with a set of certificates and keys pre-generated. However for any real-world deployment to be secure, one ***MUST*** complete the steps listed here.

##### Generate a set of keys for each server

1. Log on to each server device, and enter the bin directory.
2. For a server with index **N** issue the command: `./generate-server-key.sh N`
  1. Delete that server's CA key (first time only): `rm config/ca/ca-key-server-N`
  2. Issue certificate for that server `./issue-server-certificates.sh`
3. Collect the following files from each server and place it in a common location:
  1. Collect the server public key from server N: `config/server/keys/public-N`
  2. Collect the server certificate from server N: `config/server/certs/cert-N`
  3. Collect the server CA certificate from server N: `config/ca/ca-cert-server-N.pem`
4. Take all the files from the common location and deploy them to each server and each client:
  1. Place each server's public key into `config/server/keys/`
  2. Place each server's certificate into `config/server/certs/` 
  3. Place each server's CA certificat into `config/ca/`


##### Generate a set of keys for each client

1. For each client device, and enter the bin directory.
2. For a client with username **USER** issue the command: `./generate-client-key.sh USER`
  1. Delete the default client CA key (first time only-optional): `rm config/ca/ca-key-clients`
  2. Issue certificate for that user `./issue-client-certificates.sh`
3. Collect the following files from each client device and place it in a common location:
  1. Collect the user public key from user: `config/client/keys/public-USER`
  2. Collect the user certificate from server N: `config/client/certs/cert-USER`
  3. Collect the CA certificate used to issue the certificate: `config/ca/ca-cert-clients.pem`
4. Take all the files from the common location and deploy them to each server:
  1. Place each users's public key into `config/client/keys/`
  2. Place each user's certificate into `config/client/certs/` 
  3. Place the common client CA certificat into `config/ca/`

Note that there is no security requirement around the client CA private key, and the same client CA may be used for all users. This is because ***PROTECT*** servers always use the exact public key of the client to auhenticate, and ignore the certificate or the CA used to issue it.

Note, however, that most browsers require the server to present the client CA certificate in order to prompt the user to provide one.  This is why the client CA certificate must be known to servers. This is not an issue for command line interaction via cURL where client certificate authentication can be forced.

#### Common Configuration

The common configuration file: `config/server/common.config` specifies all information about the system necessary for both servers and clients to operate. It indicates the number of servers, their locations on the network, and various thresholds.

To start, the only configuration options that need to be specified are `num_servers` and the IP addresses of each of the servers.  Note that any network addresses with servers greater than `num_Servers` are ignored and can be left in the file.

The other parameters are automatically derived from `num_servers` but can be overridden if desired so long as they do not violate the following defined constraints.  Each of the parameters of the common config file are desribed below.

**Video demonstration of editing common.config:**

[![Alt text](https://img.youtube.com/vi/BHM17XE6ZhQ/0.jpg)](https://www.youtube.com/watch?v=BHM17XE6ZhQ)


##### Number of Servers

```bash
# Total number of servers (n)
# ===========================
# This should be equal to the total number of unique servers
# and also represents the number of shareholders, the number 
# of shares created, and the number of BFT replicas
#
# Constraints:
#   n  >  0
num_servers = 5
```
##### Server Network Addresses

```bash
# Each server's address and port
================================
# Port numbers should be be greater than 1024, and must be 
# separated by at least 2 and less than 65335.
#
# Note that not only will the specified port "x" be opened but 
# the BFT will also use ports (x+200) and (x+201).
#
# Client services will be supported on ports 8080 + serverIndex
server.1 = 127.0.0.1:65010
server.2 = 127.0.0.1:65020
server.3 = 127.0.0.1:65030
server.4 = 127.0.0.1:65040
server.5 = 127.0.0.1:65050
server.6 = 127.0.0.1:65060
server.7 = 127.0.0.1:65070
server.8 = 127.0.0.1:65080
server.9 = 127.0.0.1:65090
```

##### Secret Reconstruction Threshold

```bash
# Reconstruction threshold (k)
# ============================
# This is the number of shares and correspondingly shareholders 
# required to participate in restoring or performing an operation 
# with the shared secret. If fewer than k shares survive, recovery 
# is made impossible, therefore maximum faults for durability of 
# the secret is (n - k) while maximum faults for confidentiality is 
# given by (k - 1). These are both maximized when k is set to 
# roughly 1/2 of n.
#
# Constraints:
#   k  <=  n
#   k  >   f_S
# Optimum/default value:
#   k  =  floor((n - 1) / 2) + 1
#reconstruction_threshold = 3
```

##### Safey Fault Tolerance

```bash
# Maximum tolerable faults for safety (f_S)
# =========================================
# This number defines the maximum faults for safety of the tunable 
# layer. This can ensure integrity and confidentiality of the secret in the 
# event that more than one third but less than one half of the servers
# are corrupted. While technically f_S could be greater than one half 
# then at least one of confidentiality and secrecy of the secret would be lost.
#
# Note that for each increase in f_L by 1, maximum f_S decreases by 2.
#
# Constraints:
#   f_S  >=  0
#   f_S  <   k
#   f_S  <=  n - (2 * f_L) - 1
# Optimum value for greatest safety (default):
#   f_S  =  k - 1
# Optimum value for greatest liveness:
#   f_S   =  f_L   =    floor((n - 1) / 3)
#max_safety_faults = 2
```

##### Liveness Fault Tolerance

```bash
# Maximum tolerable faults for liveness (f_L)
# ===========================================
# This number defines the maximum faults for liveness of the tunable layer.
# This value can be adjusted downwards for increases in f_S, or upwards 
# until it converges with f_S and the one third bound of the BFT layer's 
# maximum fault tolerance.  When f_S is maximized, f_L is approximately 
# one fourth of n.
#
# Note that for each decrease in f_L by 1, maximum f_S increases by 2.
#
# Constraints:
#   f_L  >=  0
#   f_L  <=  f_S
#   f_L  <=  floor((n - f_S - 1) / 2)
# Optimum value for greatest safety (default):
#   f_L  =   n - floor((n-1) / 2) - 1
# Optimum value for greatest liveness:
#   f_L   =   f_S   =   floor((n - 1) / 3)
#max_liveness_faults = 1
```

##### Broadcast Channel Fault Tolerance

```bash
# BFT fault tolerance (f)
# =======================
# This represents the total number of faults tolerated by the 
# BFT service. Beyond this level all guarantees of the BFT are 
# lost (e.g., messages may be delivered in different orders to 
# different shareholders). Limited to roughly 1/3rd of n.
#
# Constraints:
#   f  >=   0 
#   f  <=  floor((n - 1) / 3)
# Optimum/Default value:
#   f  =   floor((n - 1) / 3)
#max_bft_faults = 1
```

#### Client Access Controls

[![Alt text](https://img.youtube.com/vi/DXvrh1b8GH4/0.jpg)](https://www.youtube.com/watch?v=DXvrh1b8GH4)

Supports fine-grained user access conrols.
Uses client-side certificate authentication over TLS
Debug authentication by going to (show URL of id check page).
Describe each permission, meaning.

### Launching Servers

[![Alt text](https://img.youtube.com/vi/H4rX8gtqjrI/0.jpg)](https://www.youtube.com/watch?v=H4rX8gtqjrI)

Unqique server ID, all need to start for service to begin.

```bash
$ git clone https://github.com/jasonkresch/protect.git
$ cd protect && ./build.sh
$ cd bin && ./start-all-servers.sh 5
$ cd bin && ./stop-all-servers.sh 5
```

If running each on a different node, then directly invoke the `./run-server` script.

## Operations

### Interacting with System

Servers listen over HTTPS, on ports 8081 - 808n where n is number of servers.  Each server id.

#### Browser Interaction

Exploring system, servers, secrets, shares. (With read permission)
Configuring CA certificates (avoid SSL error).
Note: each server uses its own CA to issue its certificates.  These may be generated individually at each sever, then collected and distributed to all.  CA itself not checked, only used for client browsers. Servers' use direct Public key matching.

(Include Screen Shots here)

          Browser (Firefox)
                    Import server CAs
                    Import user p12 file
                        Importing with firefox, default password "password".

#### Command Line Interction

Initiating a DKG
Getting share info
Deleting a share
Performing Exponentiation (Getting json)
Performing signature generation (getting json)

Mention using &json, for info, read, exponentiate, sign. MAkes parsing easier if doing so programattically.

```
curl --cacert pross-server/config/ca/ca-cert-server-5.pem --cert pross-server/config/client/certs/cert-administrator --key pross-server/config/client/keys/private-administrator "https://localhost:8085/exponentiate?secretName=prf-secret&x=8968264028836463479781803114377394639649772089185025260875842702424765933290&json=true" | jq .


curl --cacert pross-server/config/ca/ca-cert-server-5.pem --cert pross-server/config/client/certs/cert-administrator --key pross-server/config/client/keys/private-signing_user "https://localhost:8085/exponentiate?secretName=rsa-secret&message=896826402883" | jq .


curl --cacert pross-server/config/ca/ca-cert-server-5.pem --cert pross-server/config/server/certs/cert-2 --key pross-server/config/server/keys/private-2 https://localhost:8085/partial?secretName=prf-secret


curl --cacert pross-server/config/ca/ca-cert-server-5.pem --cert pross-server/config/server/certs/cert-2 --key pross-server/config/server/keys/private-2 https://localhost:8085/partial?secretName=prf-secret | jq .

curl --cacert pross-server/config/ca/ca-cert-server-5.pem --cert pross-server/config/client/certs/cert-1 --key pross-server/config/client/keys/private-1 https://localhost:8085/id
```

### Secret Management

#### Generating a random secret

#### Storing a specific secret

Must be done before DKG is performed. Must have store permission.

```
$ ./store-secret.sh config administrator prf-secret WRITE 312
```


#### Generating an RSA Private Key

./threshold-ca.sh config signing_user rsa-secret GENERATE threshold-ca.pem "CN=threshold"
openssl x509 -text -noout -in threshold-ca.pem 

 (Note, no private key anywhere, it was thresholdized and stored to the servers as shares)  We leave the public key here to get the issuer name and also to double-check the resulting certificate's validity. Exists in RAM only, and only temporarily.


#### Reading a stored secret

```
$ ./store-secret.sh config administrator prf-secret READ
```

Must have read permission.

### Cryptograpic Operations

#### ECIES Decryption

./ecies-encrypt.sh config/ administrator prf-secret ENCRYPT secret.txt out.enc
./ecies-encrypt.sh config/ administrator prf-secret DECRYPT  out.enc restored.txt


#### Certificate Issuance

$ openssl ecparam -name prime256v1 -genkey -noout -out priv-key.pem && openssl ec -in priv-key.pem -pubout -out pub-key.pem

$ ./threshold-ca.sh config signing_user rsa-secret ISSUE threshold-ca.pem pub-key.pem new-cert.pem "CN=example-entity" 
$ openssl verify -verbose -CAfile threshold-ca.pem new-cert.pem
$ openssl x509 -text -noout -in new-cert.pem


6. Managing Secrets
[![Alt text](https://img.youtube.com/vi/ZMjMlC52MJc/0.jpg)](https://www.youtube.com/watch?v=ZMjMlC52MJc)

7. Cryptographic Operations
[![Alt text](https://img.youtube.com/vi/hVjxZmUPwlU/0.jpg)](https://www.youtube.com/watch?v=hVjxZmUPwlU)

## Design

P
Link to Tunable Secrity eprint paper.

### System Architecture

![alt text](https://raw.githubusercontent.com/jasonkresch/protect/master/docs/diagrams/system-architecture.png "System Architecture")

System Architecture Diagram, componenets and their interrelations

Define asynchronous, as eventually synchronous

Describe system architecture
How Shareholders are connected, how they communicate

### Protocols

At the core of ***PROTECT's*** Distributed Key Genearation, Share Refresh, and Share Recovery Protocols is a single operation we call a *Multiple Asynchronous Publicly Verifiable Secret Sharing* (Multi-APVSS).  One round of a Multi-APVSS consists of each shareholder performing a single APVSS to all the shareholders.

An APVSS is a [Publicly Verifiable Secret Sharing](https://en.wikipedia.org/wiki/Publicly_Verifiable_Secret_Sharing) (PVSS) designed to operate over an asnchronous network.

[Verifiable Secret Scharing](https://en.wikipedia.org/wiki/Verifiable_secret_sharing) that is verifiable by anyone. Such schemes are known as .

### Fault Tolerances



Definition of faults, fault types
Byzantine faults, deviations from porotocols, malicious coordination and collusioon, working to defeat protocols. Can do anything, except forge messages from shareholders that adversary has not compromised.
Types of faults:
- crash faults, lose state, corrupt state, unresponsive, disruptive, deviate from protocol, arbitrarily ,even in coordinated ways.

![alt text](https://raw.githubusercontent.com/jasonkresch/protect/master/docs/diagrams/fault-tolerances.png "Fault Tolerances within PROTECT")





### Future Improvements

Over a longer time horizion the ***PROTECT*** project aims to support:

#### More Signature Schemes
* Schnorr Signatures (possibly leveraging Share Conversion)
* ECDSA Signatures

#### Multiparty Computation
* Share Addition
* Share Multiplication
* Threshold AES

#### RSA Extensions
* RSA Distributed Key Generation
* RSA Proactive Refresh
* RSA Share Recovery

#### Post-Quantum Cryptography


## References


This project implements the Proactive Secret Sharing (PROSS) protocol, first described in 1995 by Amir Herzberg, Stanislaw Jarecki, Hugo Krawczyk, and Moti Yung in their paper ["Proactive Secret Sharing Or: How to Cope with Perpetual Leakage"](https://pdfs.semanticscholar.org/d367/55ccc7902e3e09db5c82897401ab0877df3d.pdf).

Additionally, this project implements the Distributed Key Generation (DKG) protocol, first described in 1999 by Rosario Gennaro, Stanislaw Jarecki, Hugo Krawczyk, and Tal Rabin in their 1999 paper ["Secure Distributed Key Generation for Discrete-Log Based Cryptosystems"](https://groups.csail.mit.edu/cis/pubs/stasio/vss.ps.gz).

Both of these protocols depend on an atomic broadcast channel. In the real world of asynchronrouns networks and distributed systems the idealization of an atomic broadcast channel must be built on top of a distributed, byzantine-fault-tolerant, consensus system.  Therefore network communication among the component servers of the PROSS and DKG systems uses [Byzantine Fault Tolerant (BFT) State Machine Replication (SMR)](http://repositorio.ul.pt/bitstream/10451/14170/1/TR-2013-07.pdf) based on the [BFT-SMaRt library](https://github.com/bft-smart/library).

More references:
- Victor Shoup's Practical Threshold RSA Signatures
- BLS Signatures
- Ellipc Curve Pairing
- Blind Signatures (Chaum)
- Other references from NIST submission
- Ford-Kaliski on password hardening
- NIST Draft on Threshold Security
https://www.nongnu.org/libtmcg/dg81_slides.pdf

    Link to papers in the source (and on the GitHub page, victor shoup, etc., BLS signatures, pairing, blind RSA signatures, chaum, Hugo's TOPPS, paper, etc.)  Use references from NIST paper
    Include NIST draft paper, presentation slides?
        Respond to the commenter about running it

## Team

***PROTECT*** was designed and implementated by a team that includes experts from the fields of threshold cryptography and Byzantin fault tolerant systems. The team members include:

* Christian Cachin - Professor of Computer Science, University of Bern 
* Hugo Krawczyk - IBM Fellow, Distinguished Research Staff Member, IBM Research
* Tal Rabin - Distinguished RSM, Manager cryptographic research, IBM Research
* Jason Resch - Senior Technical Staff Member, IBM 
* Chrysa Stathakopoulou - PhD Researcher, IBM Research

## Contributing
Contributions welcome! See [Contributing](CONTRIBUTING.md) for details.

## Related Projects

- DKG implementation
- Thunderella
- https://en.wikipedia.org/wiki/Vanish_(computer_science)
