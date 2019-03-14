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

* **Store Share** - Stores a specified share to enable reliable maintenance of a specific secret
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
However this will launch protect using default configuration parameters, with default (***not secure***) keys, and running all instances on a single machine (***not reliable***).  The following subsections provide details on how to deploy ***PROTECT*** in a secure and reliable manner.

### Downloading PROTECT

There are two options for downloading protect: 1. as a ZIP file and 2. using `git`.

#### Checking out via git

***PROTECT*** may be checked out using the `git` command.  This is recommended if one wants to make changes to the code base.

Github provides two URLs for checking out the project, one via HTTPS and the other via SSH. If you intend to authenticate to Github using ssh keys, you should use the SSH method.  Otherwise the HTTPS method can be used.

**Video demonstration of dowloading PROTECT using git:**

[![Alt text](https://img.youtube.com/vi/9sDgPOUpADw/0.jpg)](https://www.youtube.com/watch?v=9sDgPOUpADw)

##### Checking out via HTTPS

Checking out PROTECT via HTTPS can be accomplished with the following command:

`$ git clone https://github.com/jasonkresch/protect.git`

##### Checking out via SSH

Checking out PROTECT via SSH can be accomplished with the following command:

`$ git clone git@github.com:jasonkresch/protect.git`

### Downloading ZIP file

One can download ***PROTECT*** by clicking the green "Clone or download" button at the top-right of this page, and then clicking the link labeled "Download ZIP" or by clicking this following link:

https://github.com/jasonkresch/protect/archive/master.zip

Note that this option requires extracting the ZIP file using an unzip utility or archive manager.

### Building

Once downloaded the entire project can be compiled into two self-contained jar files by running the "build.sh" script contained in the base directory of the protect project. Details are included in the following subsections.

#### Dependencies

**PROTECT** is written in Java 1.8 but also includes some examples in python.  It uses `maven` to for dependency management and for building.  On a fresh Ubuntu install the following packages may need to be installed in order to compile and launch ***PROTECT***.

```bash
# Determine latest versions of available packages
$ sudo apt-get-update

# Required for building and running
$ sudo apt-get install openjdk-8-jdk-headless maven

# Required for examples below
$ sudo apt-get install git python curl jq html2text openssl
```

#### Compiling

Once the above prerequisites are installed PROTECT may be built by invoking the `build.sh` script.

**Video demonstration of compiling PROTECT into jar files:**

[![Alt text](https://img.youtube.com/vi/Cz9VV0FzW10/0.jpg)](https://www.youtube.com/watch?v=Cz9VV0FzW10)

**Commands to perform download and compilation:**

```bash
$ git clone https://github.com/jasonkresch/protect.git
$ cd protect
$ ./build.sh
```
The end result of the build script is a two self-contained jar files:

Server: `pross-server/target/pross-server-1.0-SNAPSHOT-shaded.jar`

Client: `pross-client/target/pross-client-1.0-SNAPSHOT-shaded.jar`

This client jar file contains all example client functionality while the server jar file contains all shareholder server functionality.

### Configuration

The following subsections detail how to configure ***PROTECT*** to run in a secure way.

#### Keys and Certificates

For ease of getting started, ***PROTECT*** comes with a set of certificates and keys pre-generated. However for any real-world deployment to be secure, one ***MUST*** complete the steps listed here.

##### Generate a set of keys for each server

1. Log on to each server device, and enter the bin directory.
2. For a server with index **I** issue the command: `./generate-server-key.sh I`
    1. Delete that server's CA key (first time only): `rm config/ca/ca-key-server-I`
    2. Issue certificate for that server `./issue-server-certificates.sh`
3. Collect the following files from each server and place it in a common location:
    1. Collect the server public key from server I: `config/server/keys/public-I`
    2. Collect the server certificate from server I: `config/server/certs/cert-I`
    3. Collect the server CA certificate from server I: `config/ca/ca-cert-server-I.pem`
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

***PROTECT*** supports fine-grained user access controls. Each user can be granted any of 10 defined permissions to each secret.  Access controls are defined in the config file `config/client/clients.config`.

**Video demonstration of editing clients.config and configuring Firefox with a client certificate:**

[![Alt text](https://img.youtube.com/vi/DXvrh1b8GH4/0.jpg)](https://www.youtube.com/watch?v=DXvrh1b8GH4)


##### Format of Client Configuration File

```bash
# This file contains a list of clients and their permissions for what operations they can perform on which secrets
#
# Each entry in this file is of the following form:
# [secret-name]
# username_1 = <generate,/store,/read,/info,/delete,/recover,/disable,/enable,/exponentiate,/sign>
# username_2 = <generate,/store,/read,/info,/delete,/recover,/disable,/enable,/exponentiate,/sign>

# Note that the [username] must match a public key stored in the client "keys" directory with the name "public-[username]"
```

##### List of Permissions

```bash
# Permissions: A comma-separated list of permissions, supported permissions include:
#   - generate:     The ability to execute a DKG using this name to establish a secret (if one does not already exist with this name)
#   - store:        The ability for a client to directly store shares of a secret to this key name (if one does not already exist with this name)
#   - read:         The ability to recover a secret from its shares (should only be used for secrets that can be stored)
#   - info:         The ability to request information about this key, including the name, creation time, epoch, last-refresh time, prime field and group information (RSA/DH/EC)
#   - delete:       The ability to destroy the shares associated with this key, resetting its state and allowing a new key of this name to be created or stored.
#   - recover       The ability to initiate a share recovery for shares of this key after one the shares becomes lost or deleted.
#   - disable:      The ability to temporarily disable client actions from being performed against the shares of this key (note: does not prevent delete/enable/info)
#   - enable:       The ability to re-enable client actions from being performed against shares of this key
#   - exponentiate: The ability to compute an exponentiation (scalar multiply for EC curves) on a client-supplied base point: base^secret
#   - sign:         The ability to perform an signature operation on a client-supplied message: message^(secret=d) mod N.  Secrets of this form must be stored and be under RSA or BLS groups.
```

##### Example Secret Definition

```bash
[prf-secret]
administrator       = generate,delete,disable,enable,info,exponentiate,read,store,recover
security_officer    = disable,info
prf_user            = exponentiate,info

[my-secret]
administrator       = generate,delete,disable,enable,info
security_officer    = disable,info
storage_user        = store,read,delete,info

[rsa-secret]
administrator       = delete,disable,enable,info
security_officer    = disable,info
signing_user        = store,sign,info
```

Above we see three secrets defined, with the names `prf-secret`, `my-secret`, and `rsa-secret`.  For each secret, different users are defined, each having different permissions.  For servers to authenticate users, the server must have a public key file of the user having a username stored with the name `config/client/keys/public-USERNAME`.

For the client to authenticate, it must use client-side certificate authentication when connecting to the server over HTTPS.  Clients should also add all of the server CA certificates, including the Client CA certificate to a set of trusted certifcates.  These certificates can be found in `config/ca/` from each of the servers.  For convience of key and certificate import for browsers, a PKCS#12 file is generated automatically when the user's public key is signed by the CA if the user's private key is present.  This file is placed in `config/client/keys/bundle-private-USERNAME.p12` and it is created with the password `password` which must be entered when importing the key.

### Launching Servers

All servers can be launched immediately by entering the `bin` directory and executing the command:

```bash
$ ./start-all-servers.sh NUM-SERVERS
```

Where `NUM-SERVERS` is the number of servers in the system. However, this command only works when all servers are run from the same machine.  If one starts all servers with this command, they can also be stopped with:

```bash
$ ./stop-all-servers.sh NUM-SERVERS
```

When running multiple servers from different nodes, one should use the command:

```bash
$ ./run-server.sh INDEX-OF-SERVER
```

Where `INDEX-OF-SERVER` is a unique integer between 1 and the total number of servers in the system.  Note that the index that is used must have the corresponding private key of the server located in `config/server/keys-private-INDEX-OF-SERVER`.

**Video demonstration of launching servers:**

[![Alt text](https://img.youtube.com/vi/H4rX8gtqjrI/0.jpg)](https://www.youtube.com/watch?v=H4rX8gtqjrI)

## Operations

The following sections detail interaction with a ***PROTECT*** deployment.

### Interacting with System

Each server listens for client connections on port (8080 + INDEX-OF-SERVER). For example, in a system of 5 shareholders, each shareholder can be accessed at at:

```
https://SHAREHOLDER-1/8081/
https://SHAREHOLDER-2/8082/
https://SHAREHOLDER-3/8083/
https://SHAREHOLDER-4/8084/
https://SHAREHOLDER-5/8085/
```

Where SHAREHOLDER-I is the IP address of the shareholder with index = i.

#### Browser Interaction

The following subsections detail how to interact with ***PROTECT*** via a web browser.


##### Main Page

*Required Permissions:* `NONE`

Because ***PROTECT*** operates over HTTPS one may use a web browser to create, manage, and use secrets.  When ***PROTECT*** starts, navigating to `https://SHAREHOLDER-1/8081/` will display the main page, which will display configuration information, the set of shareholders which support the system, and a list of secrets managed by the system.

Unless the certificates used by ***PROTECT*** servers are issued by known Certificate Authorities, browsers will generally complain that the servers are not trusted. To remedy this problem requires importing each server's CA certificate as a trusted certificate.

See: [digicert's guide to importing CA certificates](https://knowledge.digicert.com/solution/SO13734.html)

**Main page of PROTECT:**

![alt text](https://raw.githubusercontent.com/jasonkresch/protect/master/docs/screenshots/protect-main-page.png "Index page")

##### Identity Check Page

*Required Permissions:* `NONE`

While the main page may be accessed anonymously by anyone, any attempt to access, use, or obtain information about the secrets (beyond their name) will be prevented without authenticating to ***PROTECT***.  To authenticate one must import their public key and private key into the browser for use.  This can be done by importing the file `config/client/keys/bundle-private-USERNAME.p12` which is protected with the password "password".

To verify the keys are successfully imported, there is an identity check page which displays who the server believes the client to be, and also displays what permissions that user has.  This page exists at: `https://SHAREHOLDER-i/808i/id` for shareholder i.

**Identity page of PROTECT:**

![alt text](https://raw.githubusercontent.com/jasonkresch/protect/master/docs/screenshots/id-check.png "Identity Check")

##### Generate / Store Secret Page

*Required Permissions:* `INFO` to view (`GENERATE` or `STORE`) to generate or store a secret

Before a secret is generated or stored it will be in an uninitialized state.  To store a secret of a specific value requires pre-storing shares of it with each of the shareholders and then initiating a DKG.

**Generate or Store page of PROTECT:**

![alt text](https://raw.githubusercontent.com/jasonkresch/protect/master/docs/screenshots/pre-dkg.png "Generate Secret")

To obtain a sharing of a particular value, one can use the "shamir-share.py" script. The following command shows an example with number of shareholders = 5, reconstruction threshold = 3, and sharing the value "1000":

```
$ ./shamir-share.py 5 3 1000
```

Output:
```
Shares:
(1, 16780829942398145718766131207515104628060049441812475815286826296451235316215)
(2, 69445721854271011972215100496134157649123142667565881836159569062930391762336)
(3, 42202586525262349997649460916449585533192324453124457720195969238368957294994)
(4, 50843513165728408557766659417868961810264550022623963809818285883835443958558)
(5, 95368501775669187652566696000392286480339819376064400105026518999329851753028)
Secret Public Key:
(11496013529637860221919730206355387223102005066697739921363561317831349586700, 76204896272524372731756530748799401765655575344541547788929707715182487989417)
```

One would then take each of those shares and store one of each directly to the corresponding server.

Alternatively, one can initiate the DKG immediately without pre-storing shares to create shares of a random secret.

In either case, to initiate the DKG and establish the secret click the "Initiate DKG" button.

**Video demonstration of generating a secret and self healing:**

[![Alt text](https://img.youtube.com/vi/ZMjMlC52MJc/0.jpg)](https://www.youtube.com/watch?v=ZMjMlC52MJc)

##### Share Information Page

*Required Permissions:* `INFO`

Once a secret is established this info page will change from the Generate or Store page to a page displaying information about the secret.

It lists the public key of the secret, the group and field information, and the shareholder public keys.

**Share Information page of PROTECT:**

![alt text](https://raw.githubusercontent.com/jasonkresch/protect/master/docs/screenshots/secret-information.png "Secret Information")

##### Read Share Page

*Required Permissions:* `READ`

With the `READ` permission, one can read the raw value of a share, providing the capacity to recover the raw secret.  This permission is typically only given for secrets that are stored.

**Read Share page of PROTECT:**

![alt text](https://raw.githubusercontent.com/jasonkresch/protect/master/docs/screenshots/read-share.png "Read Share")

#### Command Line Interaction

All of the interactions that are possible through a web browser can be invoked via command line utilities such as "cURL".  This can be used to write automated scripts and applications. In addition, many of the APIs support a flag to return the output in *JSON*--a machine parsable format that simplifies processing of responses by applications.


##### Get Client Identity information via cURL

The following command is an examaple of obtaining the identity information from a ***PROTECT*** server running as a shareholder with index 1 and authenticating as the user *administrator*:

```bash
curl --cacert config/ca/ca-cert-server-1.pem --cert config/client/certs/cert-administrator --key config/client/keys/private-administrator https://localhost:8081/id | html2text
```

Output:

```
You have authenticated as 'administrator'.

You have the following permissions:

my-secret
    * GENERATE
    * INFO
    * DELETE
    * DISABLE
    * ENABLE

rsa-secret
    * INFO
    * DELETE
    * DISABLE
    * ENABLE

prf-secret
    * GENERATE
    * STORE
    * READ
    * INFO
    * DELETE
    * RECOVER
    * DISABLE
    * ENABLE
    * EXPONENTIATE
```

##### Store Share via cURL

There are two ways of storing a share of a secret to ***PROTECT*** one is for secrets over an Elliptic Curve group, and can be used for ECIES, ECDH, OPRF, and other operations via the `GENERATE` call. The other is to store a share of an RSA key. Storing shares of an RSA key can allow calls to `SIGN`.

###### Store Elliptic Curve Share

The following command is an examaple of storing a share of the secret "1000" having a value of *16780829942398145718766131207515104628060049441812475815286826296451235316215* to a ***PROTECT*** server running as a shareholder with index 1 and authenticating as the user *storage_user*:

```bash
$ curl --cacert config/ca/ca-cert-server-1.pem --cert config/client/certs/cert-storage_user --key config/client/keys/private-storage_user "https://localhost:8081/store?secretName=my-secret&share=16780829942398145718766131207515104628060049441812475815286826296451235316215"
```
Output:

```
s_1 has been stored, DKG will use it for representing 'my-secret' in the DKG.
```

###### Store RSA Share

The following command is an examaple of storing a share or an RSA key to a ***PROTECT*** server running as a shareholder with index 1 and authenticating as the user *signing_user*:

```bash
$ curl --cacert config/ca/ca-cert-server-1.pem --cert config/client/certs/cert-signing_user --key config/client/keys/private-signing_user "https://127.0.0.1:8081/store?secretName=rsa-secret&e=65537&n=103473605239433672988170242543400143644319618556329167288597941468783880585044744860755891943318036531628479114471645405651308652757893050422651869541014921685723605770516956182368925786350457876194164172876267931506341367115164995305663462654594362378366765664926543672950935191064350745789112227586965227913&v=89174595847525463567195138659796024553881389183729195174486088185568098465506494969619878728986175176936274201134062991704918018402744042326457662297578901935781618082021439811800776299725969143730373560068706239596299099669642165924311343152469433964341406082500651051649257301602532122964144705715709739339&v_1=67838606285772972709589636086946420179581610250472129734239753228790673888814805859199394195992311049323060626746860680534522475843626856861425244498224948490967625717997415935224286519633770095202024130167715781380557751895710445007491432720109793984792061519294955581897569031739493296547355637028466235729&v_2=49365490607479026700863538167517290765812483827500129781771433286228341351215126345765817238267616875533660071823553083533843603069475896324484818951028317813063757169751826364162562289350544976094693821579613905223548791948028150941742738518413691118263076780204375759793124634262098009499822250393938057130&v_3=70399170169480003218861751530647834162087045708118897096451809113247984113627561059474959048085724106745440834495366396302760983596034401111953555000790411666596979091233989605439434617369451714966101676686207804762895723478688012672136807011487457582172442697987305244652880337586498352869891493099956409944&v_4=3961783857571708675976410219076151745133917485317711635595061770608283982843735138339207703094017642180410314221097596897469749541785308302011009004299062194572050260293142604362740269803402396815394563817080089214192686105179492629145554516806403881871047087820945919651787634073215344291576993667283087064&v_5=57105980543489909017903447409550148455652202674350734474537216113701585408408878229765322530581962569580127421470132987825656641271491155550740038068773491753076020990326721329830790769787322154168998704249974943409186087736841621707795937528212269359601913333017914795670879284722127750939464182297253124123&share=3266332474335221848507334676466193427875612880474956052911982588842686456528877505496787394818223665966486495405835508519142171287699147344197435336220075008086394890172750159146977697724702757443712133588940630427827463235219649003761874533988659889506328095153097748438925104628611507713773689042845159093"
```

Note: ***e*** and ***n*** from above are the public exponent and RSA modulus. ***v*** and ***v_i*** are the verification generator and verification values for the shareholders computed according to Victor Shoup's ["Practical Threshold Signatures"](http://threshsig.sourceforge.net/pdfs/shoup.pdf).

Output:

```
RSA share has been stored.
```

Note that there is no need to perform a DKG after storing RSA shares to the shareholders.

##### Initiate DKG via cURL

The following command is an examaple of initiating a DKG to a ***PROTECT*** server running as a shareholder with index 1 and authenticating as the user *administrator* (note: this will trigger all active shareholders to participate):

```bash
$ curl --cacert config/ca/ca-cert-server-1.pem --cert config/client/certs/cert-administrator --key config/client/keys/private-administrator "https://localhost:8081/generate?secretName=prf-secret"
```

Output:

```
The secret 'prf-secret' has been generated in 3335 ms.
```

##### Get Share information via cURL

The following command is an examaple of obtaining information from a ***PROTECT*** server running as a shareholder with index 1 and authenticating as the user *administrator* to get information on secret "prf-secrt":

```bash
$ curl --cacert config/ca/ca-cert-server-1.pem --cert config/client/certs/cert-administrator --key config/client/keys/private-administrator "https://localhost:8081/info?secretName=prf-secret&json=true" | jq .
```

Output:

```json
{
  "public_key": [
    "85471108262864050763368858857892650522356777301172713990576035449935649444128",
    "33699575770748921809348360756692080923310245856746472560322702516895259621980"
  ],
  "share_verification_key_3": [
    "108780629008393730100706832907018626340752433314027718993435856344880929647162",
    "107945656105720484014682703741606262799424786035611034081522494147921644302877"
  ],
  "share_verification_key_2": [
    "72941157035340659419232429051730915688320405373296368274125491626754723586398",
    "103021563682848582443386637939998993330666870989027196637178470632331247135317"
  ],
  "share_verification_key_1": [
    "63799763095960153009459350185166023553244758527046022598476606734083573007857",
    "27668319345522126623940731861172972439424105149281576838317001076086984575922"
  ],
  "responder": 1,
  "epoch": 26,
  "share_verification_key_5": [
    "47427766573600383471926812380524135942220129818759619261016730896645984395322",
    "109368983451782748983263222857169783109623394285516235757600245721694691484046"
  ],
  "share_verification_key_4": [
    "84877538144686376995149588236484785497708571913711243339163609781335359407812",
    "84600981347466039197527884324745354241242431292503724855304798263102442354377"
  ]
}
```

##### Read Share via cURL

The following command is an examaple of reading a share of secret "prf-secret" from a ***PROTECT*** server running as a shareholder with index 1 and authenticating as the user *administrator*:

```bash
$ curl --cacert config/ca/ca-cert-server-1.pem --cert config/client/certs/cert-administrator --key config/client/keys/private-administrator "https://localhost:8081/read?secretName=prf-secret&json=true" | jq .
```

Output:

```json
{
  "responder": 1,
  "epoch": 36,
  "share": "79553843040925066706303531008870751210469359208744558125699487110354052898445"
}
```

##### Delete Share via cURL

*Required Permissions:* `DELETE`

The following command is an examaple of deleting a share of from a ***PROTECT*** server running as shareholder with index 1 and authenticating as the user *administrator* to delete a share of the secret named *prf-secre*:

```bash
$ curl --cacert config/ca/ca-cert-server-1.pem --cert config/client/certs/cert-administrator --key config/client/keys/private-administrator "https://localhost:8081/delete?secretName=prf-secret"
```

Output:
```
prf-secret has been DELETED.
```

##### Perform Exponentiation via cURL

*Required Permissions:* `EXPONENTIATE`

The following command is an examaple of obtaining a share of an exponentiation with an elliptic curve base point (x = *39522464597546680434308646015259477026906557798165815565761410653690318807746*, y = *300250275475100976592897958924554703173715402382388912994734131264810025115*) from a ***PROTECT*** server running as shareholder with index 1 and authenticating as the user *administrator* using a share of the secret named *prf-secre* and getting the output in JSON format:

```bash
$ curl --cacert config/ca/ca-cert-server-1.pem --cert config/client/certs/cert-administrator --key config/client/keys/private-administrator "https://localhost:8081/exponentiate?secretName=prf-secret&x=39522464597546680434308646015259477026906557798165815565761410653690318807746&y=300250275475100976592897958924554703173715402382388912994734131264810025115&json=true" | jq .
```

Output:
```json
{
  "base_point": [
    "39522464597546680434308646015259477026906557798165815565761410653690318807746",
    "300250275475100976592897958924554703173715402382388912994734131264810025115"
  ],
  "responder": 1,
  "result_point": [
    "112877074676220790712663792135696517254351430132098997431865646117621239767928",
    "114368565126077038137024926861461505752538737384458050918690817623772672914888"
  ],
  "epoch": 7,
  "compute_time_us": 239
}
```

##### Perform RSA Sign via cURL

*Required Permissions:* `SIGN`

The following command is an examaple of obtaining a share of a signature for message *896826402883* from a ***PROTECT*** server running as shareholder with index 1 and authenticating as the user *signing_user*:

```bash
$ curl --cacert config/ca/ca-cert-server-1.pem --cert config/client/certs/cert-signing_user --key config/client/keys/private-signing_user "https://localhost:8081/sign?secretName=rsa-secret&message=896826402883" | jq .
```

Output:
```json
{
  "share_proof": [
    "3915452739578001858942546666196052929410007440085891066762307417431530661042",
    "20964253121137168757054695370851318724278361189297787721452176888381860654341018763771579904658908644586905464579631038665144628410438333078449478057400360255772779493977754763560993888480299677654104394117575673086007371914651508268671705050103161261637017122053108665057274898007548233105981668219010087391804092402409505734758873751230149970499236181397080628186536065495498362947118619352171281091444936226477721131886591732284307974122396541650519952297548"
  ],
  "e": "65537",
  "v": "97667882916481129410985948086978181466870029133460868393672413700250085965239088892639364190258750946882209853020038374719189973167303815159003907235872041083950526069327190866375257364337233176456207853278278220036538074809655478895273438356455808813663052856690027569210092504427400981359651564618352610913",
  "verification_keys": [
    "92527974764854322558056028036618734049092140046287806571484563485844975123883935116846254078525219756309599587353804113068401847427417295124603413078730074680506712173963038311941133801360119308920756165024775989205520863697439485292170664359232457750076317155390109911570648356146181339113520584853863113996",
    "26628390956049558909765449115153405859473515974079432909826575060219411640299591044128638109269155505246795187574942014539499529478701803491553109327331354962622645924100557338460271759789590417002388765290066954882298380164277735375809612788254019209437452364374199311585860798446280384820933409698839070312",
    "25884028479267464279813975344450333535498341897294482438123990128747086626536082464529718043160830674933036651191020276199392937497850513350228880856464170681214341645622314433889320678946439188357119795238878346941705557272925749521095180147059416590580171564616032217191588401389241728146720866836136731697",
    "10951079262237060198735117097526209001738002413408487030354005665264687578843599129644461818289818622367843548419295966164938958765720004351465972803393379896767005715587983148561448996926711467153226555539906867880483688830933570989310955525583122376320513655775954862591548049602633385722131986134299114803",
    "11458512971360055709776301799447289870783316078774550062528720833067260425198740600379419669700669970554985569018475280146869841717144244008344189442674764151374799148597011638098551579922344543628496526020162222698947158494191359089520517472462936695192891442805952237247445941507567210349660814764633664024"
  ],
  "responder": 1,
  "epoch": 0,
  "share": "104089335183339073298944949497737540916579012158418210606751223528587785608052573296790876200612808800484308696637642182475782012135170819868407737528710134231944072736612956448438988789849478774665339898114642434511602879101191200695064054918514262681391731499065584278925847132588968569887873172333820329507",
  "compute_time_us": 1596,
  "n": "124177666122443695422631704923632259112074454777939228513534798824013949965600400022841037928624034703021632895189346228095215347041503409017302928792689704702196734683455596239280440525569622847255966426180465184920746438085691791941567916885533614179535146478855720578404954663150192227022545981178180789901"
}
```

### Example Clients

The following sections show interacting with ***PROTECT*** via some example client utilities. Tehse utilities allow one to store and retrieve a secret, to encrypt and decrypt a file, and to generate a CA and issue certificates.

**Video demonstration of using Encryption and Signing Clients:**

[![Alt text](https://img.youtube.com/vi/hVjxZmUPwlU/0.jpg)](https://www.youtube.com/watch?v=hVjxZmUPwlU)

#### Read / Write Client Utility

The "store-secret.sh" script allows one to store a secret which is shared across an instance of ***PROTECT*** servers.  It can only be retrieved by obtaining shares from a reconstruction threshold number of shareholders.

##### Storing a specific secret

*Required Permissions:* `STORE`

Note: This command must be done before DKG or RSA storage is performed. Once a value is stored for a given secret, it cannot be changed.

The following command uses the *administrator* user to store the value "312" to the secret *prf-secret*:

```
$ ./store-secret.sh config administrator prf-secret WRITE 312
```

Output:

```
ServerConfiguration [numServers=5, maxBftFaults=1, reconstructionThreshold=3, maxSafetyFaults=2, maxLivenessFaults=1, serverAddresses=[/127.0.0.1:65010, /127.0.0.1:65020, /127.0.0.1:65030, /127.0.0.1:65040, /127.0.0.1:65050]]
-----------------------------------------------------------
Generating shares of the provided secret...
Public key of secret = EcPoint [x=65608896125016205438866197687472864343298993954507265304330251799823014917901, y=75156640000588750534718968597079516099023719578833800727861780634148843964693]
Generation of shares complete.

Storing shares to secret: prf-secret...  (done)
Initiating DKG for secret: prf-secret...  (done)
Server returned HTTP response code: 409 for URL: https://127.0.0.1:8085/generate?secretName=prf-secret
 (done)
Accessing public key for secret: prf-secret...  (done)
Stored Public key for secret:    EcPoint [x=65608896125016205438866197687472864343298993954507265304330251799823014917901, y=75156640000588750534718968597079516099023719578833800727861780634148843964693]

DKG complete. Secret is now stored and available for reading.
```

##### Reading a stored secret

*Required Permissions:* `READ`

The following command uses the *administrator* user to read the value of the secret stored to *prf-secret*:

```bash
$ ./store-secret.sh config administrator prf-secret READ
```

Output:

```
ServerConfiguration [numServers=5, maxBftFaults=1, reconstructionThreshold=3, maxSafetyFaults=2, maxLivenessFaults=1, serverAddresses=[/127.0.0.1:65010, /127.0.0.1:65020, /127.0.0.1:65030, /127.0.0.1:65040, /127.0.0.1:65050]]
-----------------------------------------------------------
Accessing public key for secret: prf-secret...  (done)
Stored Public key for secret:    EcPoint [x=65608896125016205438866197687472864343298993954507265304330251799823014917901, y=75156640000588750534718968597079516099023719578833800727861780634148843964693]

Reading shares to decode secret: prf-secret
Public key of recvered secret = EcPoint [x=65608896125016205438866197687472864343298993954507265304330251799823014917901, y=75156640000588750534718968597079516099023719578833800727861780634148843964693]
done.

Value of secret: 312
```

Note: we obtain the same value "312" that we previously stored for this secret.

#### Certificate Authority Client

The "threshold-ca.sh" script allows one to generate a CA certifiate whose private key is stored across an instance of ***PROTECT*** servers.  It can then be used to issue certificates only through interaction with a threshold number of shareholders to obtain shares of a signature.  The private key itself is never reconstructed during the signing operation.

##### Generating a new RSA Private Key

*Required Permissions:* `STORE` and `GENERATE`

The following command uses the *signing_user* user to create and store a new RSA private key to secret *rsa-secret* and output a CA certificate to a file *threshold-ca.pem*. It then shows how to use openssl to view the newly created CA certificate:

```bash
# Create a new CA certifiate whose private key is stored to a secret
$ ./threshold-ca.sh config signing_user rsa-secret GENERATE threshold-ca.pem "CN=threshold"

# View the created digital certificate of the CA
$ openssl x509 -text -noout -in threshold-ca.pem 
```

Output:

```
erverConfiguration [numServers=5, maxBftFaults=1, reconstructionThreshold=3, maxSafetyFaults=2, maxLivenessFaults=1, serverAddresses=[/127.0.0.1:65010, /127.0.0.1:65020, /127.0.0.1:65030, /127.0.0.1:65040, /127.0.0.1:65050]]
-----------------------------------------------------------
Beginning generation of threshold RSA key...
  Generating p... done.
  Generating q... done.
  Computing moduli... done.
  Creating RSA keypair... done.
  Generating secret shares... done.
  Creating public and private verification keys... done.
RSA Key Generation complete.

Creating self-signed root CA certificate for: CN=threshold
Certificate written to: /home/jresch/eclipse-workspace/protect-project/protect/bin/threshold-ca.pem

Storing shares of RSA private key to secret: rsa-secret... Storage complete
 (done)
CA Creation Completed. Ready to issue certificates.
WARNING: Refresh and reconstruction are not active for RSA keys, do not use them for encrypting anything that must be recovered
```

Note: the RSA private key is not persisted anywhere, it is turned into shares and distributed across the servers as shares. It exists on the machine that it was generated from in RAM only and only temporarily.  Aftewards, it can be used to create RSA signatures ***without*** ever having to restore the private key at any location.

##### Issuing a Certificate with the RSA Private Key

*Required Permissions:* `INFO`, `SIGN`

The following command uses the *signing_user* user to issue a new end-entity certificate signed by the RSA private key held by the secret *rsa-secret* using the issuer name from the CA certificate file *threshold-ca.pem*, and outputting the newly created certificate to the file *new-cert.pem* with the public key in file *pub-key.pem*. It then shows how to use openssl to verify and view the newly created CA certificate:

```bash
# Generate new EC key pair (the following command needs only the public key of the end-entity)
$ openssl ecparam -name prime256v1 -genkey -noout -out priv-key.pem && openssl ec -in priv-key.pem -pubout -out pub-key.pem

# Uses the private key represented by the shared secret to issue a new digital certificate
$ ./threshold-ca.sh config signing_user rsa-secret ISSUE threshold-ca.pem pub-key.pem new-cert.pem "CN=example-entity" 

# Verifies that the newly issued certificate is valid
$ openssl verify -verbose -CAfile threshold-ca.pem new-cert.pem

# Vies the newly created certificate
$ openssl x509 -text -noout -in new-cert.pem
```

Output:

```
ServerConfiguration [numServers=5, maxBftFaults=1, reconstructionThreshold=3, maxSafetyFaults=2, maxLivenessFaults=1, serverAddresses=[/127.0.0.1:65010, /127.0.0.1:65020, /127.0.0.1:65030, /127.0.0.1:65040, /127.0.0.1:65050]]
-----------------------------------------------------------
Issing certificate using threshold RSA secret: rsa-secret
  Reading end-entity public key from file: pub-key.pem... done.
  Loading CA certificate from file: pub-key.pem... done.
  Creating a To-Be-Signed Certificate for: CN=example-entity... done.
  Performing threshold signing of certificate using: rsa-secret...  [4, 2, 3]done.
Signature result obtained: 3322894367540426482083991150398644257388563945327251094369538738259726873249702020155173776859711059398638402445640888124735092191784650998497252963189638128407648280965871109887268693900255667960958932376726994781849570690812236851351668497880282165003222360160944122263984769169199188499651752780465810940

  Creating certificate using signature...   done. Certificate is valid!
Writing signed certificate to file: new-cert.pem...  done.

Operation complete. Certificate now ready for use.
```

#### ECIES Encryption Client

The "ecies-encrypt.sh" script allows one to encrypt a file with the public key of a shared secret and then later decrypt it using a private key is stored across an instance of ***PROTECT*** servers.  The private key itself is never reconstructed during the decryption operation.

##### Encrypting a File

*Required Permissions:* `INFO`

The following command uses the *administrator* user to encrypt the file "secret.txt" and output the encrypted result to a file named "out.enc", using the public key of *prf-secret* to perform that encryption:

```
# Writes a secret to a file
$ cat "This is my secret" > secret.txt

# Encrypts the file
$ ./ecies-encrypt.sh config/ administrator prf-secret ENCRYPT secret.txt out.enc
```

Output:

```
ServerConfiguration [numServers=5, maxBftFaults=1, reconstructionThreshold=3, maxSafetyFaults=2, maxLivenessFaults=1, serverAddresses=[/127.0.0.1:65010, /127.0.0.1:65020, /127.0.0.1:65030, /127.0.0.1:65040, /127.0.0.1:65050]]
-----------------------------------------------------------
Beginning encryption of file: secret.txt
Accessing public key for secret: prf-secret...  (done)
Public key for secret:    EcPoint [x=114324586278815358159403285865423707586515079119912211138349262325535939591572, y=96196372904301990529913546317445029333736110462708925299234835876317074236813]
Current epoch for secret: 0

Reading input file: secret.txt...  (done)
Read 36 bytes.

Performing ECIES encryption of file content...  (done)
Encrypted length 165 bytes.

Writing ciphertext to file: out.enc...  (done)
Wrote 165 bytes.

Done.
```

Note: the `INFO` permission is required only to get the public key of the given secret.  A user having permission to encrypt things using this client may not necessarrily have permission to decrypt things. This requires the `EXPONENTIATE` permission.

##### Decrypting a File

*Required Permissions:* `INFO`, `EXPONENTIATE`

```
# Performs decryption of the file
$ ./ecies-encrypt.sh config/ administrator prf-secret DECRYPT out.enc restored.txt

# Views the plaintext that was decrypted
$ cat restored.txt
```

Output:

```
ServerConfiguration [numServers=5, maxBftFaults=1, reconstructionThreshold=3, maxSafetyFaults=2, maxLivenessFaults=1, serverAddresses=[/127.0.0.1:65010, /127.0.0.1:65020, /127.0.0.1:65030, /127.0.0.1:65040, /127.0.0.1:65050]]
-----------------------------------------------------------
Beginning decryption of file: out.enc
Reading input file: out.enc...  (done)
Read 165 bytes of ciphertext.

Extracting public value from ciphertext: out.enc...  (done)
Public Value is: EcPoint [x=102982451109465048808421710427021373733130552241473722145177824843275289410800, y=39125118849913946305817596608474285813159876759100064987574954662484432339330]

Accessing public key for secret: prf-secret...  (done)
Public key for secret:    EcPoint [x=114324586278815358159403285865423707586515079119912211138349262325535939591572, y=96196372904301990529913546317445029333736110462708925299234835876317074236813]
Current epoch for secret: 2

Performing threshold exponentiation on public value using: prf-secret...  (done)
Shared secret obtained:    EcPoint [x=111266831548464192862795979766955168504213940072659213626271620524626303320482, y=112509428695934305816529850305850718076594762115086722743653004840956852939645]

Performing ECIES decryption of file content...  (done)
Plaintext length 36 bytes.

Writing plaintext to file: restored.txt...  (done)
Wrote 36 bytes.

Done.
```


## Design

***PROTECT*** is based on a tunable security model and protocol described in (TODO: Include link to tunable Secrity eprint.)

### System Architecture

![alt text](https://raw.githubusercontent.com/jasonkresch/protect/master/docs/diagrams/system-architecture.png "System Architecture")

Above is a high-level architecture of ***PROTECT***.  Each shareholder instance, along with all of the users are connected over an eventually synchronous network (e.g. a LAN, WAN, or Internet), which guarantees only that messages are evenutally delivered between honest parties, but the time this might take cannot be known in advance.  The network is otherwise assumed to be under the control of an adversary who can delay, re-order, drop, or corrupt messages, but cannot forge messages by clients or shareholders from whom the adversary does not know the private key.

All server-to-server communication takes place over a Byzantine Fault Tolerant atomic broadcast primitive.  ***PROTECT*** uses the BFT-SMaRt library to perform this operation (shown in orange). This layer, is subject to the 1/3 failures.  Beyond this, it cannot guarantee consistent total message order nor liveness between shareholders. To prevent such forks from causing corruption of secrets managed by ***PROTECT***, there is the Tunable Certification Layer (shown in purple). This layer collects signatures (essentially votes) from all the other shareholders as to what message they believe exists in each position in the BFT message log.

If agreement can be reached by 3/4 of the shareholders, then a message in the BFT log at a certain position is considered certified for that position in the log, and it is added to the Certified message log.  The Shareholder then reads the latest messages from this certified log in order to update its state.  Such state updates include making progress in performing a DKG or Proactive Refresh and Recovery.

All three of these operations, DKG, Refresh, and Recovery are based on a single primitive, called a Multi-APVSS, which consists of each shareholder performing an Publicly Verifiable Secret Sharing.  The result of this Multi-APVSS yields shares of the secret, as well as public verification keys for each shareholder’s share, as well as Feldman commitments to the shared polynomial.

Clients interact with the shareholder through an HTTPS API, and authenticate directly to each shareholder via client certificates over TLS.

### Protocols

At the core of ***PROTECT's*** Distributed Key Genearation, Share Refresh, and Share Recovery Protocols is a single operation we call a *Multiple Asynchronous Publicly Verifiable Secret Sharing* (Multi-APVSS).  One round of a Multi-APVSS consists of each shareholder performing a single APVSS to all the shareholders.

An APVSS is a [Publicly Verifiable Secret Sharing](https://en.wikipedia.org/wiki/Publicly_Verifiable_Secret_Sharing) (PVSS) designed to operate over an asnchronous network, unlike [Verifiable Secret Scharing](https://en.wikipedia.org/wiki/Verifiable_secret_sharing), a publically verifiable secret sharing may be verifiable by anyone who knows the public keys of the shareholders. This prevents dishonest behavior during the Multi-APVSS to result in some honest shareholders not receiving their share of the secret.

### Fault Tolerances

Faults include not only unintentional events such as software crashes, hardware failure, power outage, memory corruption, network corruption, dropped packets, but malicious and intentional deviations from the protocol in arbitrary ways, such as sending incorrect messages, duplicating messages, lying about which messages have been received in which orders to different sets of honest shareholders, failing to respond to messages, failing to relay messages, sending malformed messages, coordinating misbehavior among multiple corrupted shareholders, and so forth.  Such arbitrary failures are known as *Byzantine* faults, and it is crucial for any system aiming to be resilient to breaches of the system to tolerate them while maintaining liveness (responsiveness and availability) and safety (correctness, and privacy and durability of data).

The following chart details different fault tolerance levels for different numbers of shareholders in a ***PROTECT*** system:

![alt text](https://raw.githubusercontent.com/jasonkresch/protect/master/docs/diagrams/fault-tolerances.png "Fault Tolerances within PROTECT")

Where *f_S* is the maximum number of Byzantine faults that can occur while the system preserves ***safety***.
Where *f_L* is the maximum number of Byzantine faults that can occur while the system preserves ***liveness***.
Where *f* is the maximum number of Byzantine faults that can occur while the atomic broadcast maintains safety and livness.

In ***PROTECT***, liveness refers to the ability to make continual progress in share refresh and share recovery operations. Loss of liveness here does not prevent clients from reading or writing secrets, nor using them to perform cryptographic operations, which in general requires only the availability of (*f_S* + 1) shareholders who are at the same epoch (version of a secret).

### Future Improvements

Over a longer time horizion the ***PROTECT*** project aims to support:

#### More Signature Schemes
* EdDSA signatures
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

- ["Proactive Secret Sharing Or: How to Cope with Perpetual Leakage"](https://pdfs.semanticscholar.org/d367/55ccc7902e3e09db5c82897401ab0877df3d.pdf). Amir Herzberg, Stanislaw Jarecki, Hugo Krawczyk, Moti Yung. 10.1007/3-540-44750-4_27, 1995, CRYPTO.
- ["Practical Threshold Signatures"](http://threshsig.sourceforge.net/pdfs/shoup.pdf), Victor Shoup
- ["Secure Distributed Key Generation for Discrete-Log Based Cryptosystems"](https://groups.csail.mit.edu/cis/pubs/stasio/vss.ps.gz), Rosario Gennaro, Stanislaw Jarecki, Hugo Krawczyk, and Tal Rabin, (1999)
- ["State Machine Replication for the Masses with BFT-SMART"](http://repositorio.ul.pt/bitstream/10451/14170/1/TR-2013-07.pdf). Alysson Bessani, João Sousa, Eduardo E. P. Alchieri. 2014, DSN '14 Proceedings of the 2014 44th Annual IEEE/IFIP International Conference on Dependable Systems and Networks, Vol. 44, pp. 355-362.
- ["Non-Interactive and Information-Theoretic Secure Verifiable Secret Sharing"](https://www.cs.cornell.edu/courses/cs754/2001fa/129.PDF). Pedersen, Torben P. ISBN:3-540-55188-3, 1991, CRYPTO '91 Proceedings of the 11th Annual International Cryptology Conference on Advances in Cryptology, pp. 129-140.
- ["Aggregate and Verifiably Encrypted Signatures from Bilinear Maps"](https://crypto.stanford.edu/~dabo/pubs/papers/aggreg.pdf), Dan Boneh, Craig Gentry, Ben Lynn, Hovav Scaham, (2003)
- ["Blind Signatures for Untraceable Payments"](https://sceweb.sce.uhcl.edu/yang/teaching/csci5234WebSecurityFall2011/Chaum-blind-signatures.PDF), David Chaum, (1998)
- ["TOPPSS: Cost-minimal Password-Protected Secret Sharing based on Threshold OPRF"](https://eprint.iacr.org/2017/363.pdf). Stanislaw Jarecki, Aggelos Kiayias,Hugo Krawczyk, Jiayu Xu. 10.1007/978-3-319-61204-1_3, 2017, Applied Cryptography and Network Security: 15th International Conference, pp. 39-58.
- ["Threshold Partially-Oblivious PRFs with Applications to Key Management"](https://eprint.iacr.org/2018/733.pdf). Stanislaw Jarecki, Hugo Krawczy, Jason Resch. 2018, Cryptology ePrint Archive: Report 2018/733.
- ["Server-Assisted Generation of a Strong Secret from a Password"](http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.17.9502&rep=rep1&type=pdf), Warwick Ford, Burton S. Kaliski Jr., (2000)
- [Distributed Key Generation in the Wild](https://eprint.iacr.org/2012/377.pdf), Aniket Kate, Yizhou Huang, Ian Goldberg, (2012)
- ["Threshold Schemes for Cryptographic Primitives: Challenges and Opportunities in Standardization and Validation of Threshold Cryptography"](https://csrc.nist.gov/publications/detail/nistir/8214/final)
- ["Highly-Efficient and Composable Password-Protected Secret Sharing (Or: How to Protect Your Bitcoin Wallet Online)"](https://eprint.iacr.org/2016/144.pdf). Stanislaw Jarecki, Aggelos Kiayias, Hugo Krawczyk, Jiayu Xu. 10.1109/EuroSP.2016.30, 2016, 2016 IEEE European Symposium on Security and Privacy (EuroS&P).
- ["SPHINX: A Password Store that Perfectly Hides Passwords from Itself"](http://webee.technion.ac.il/~hugo/sphinx.pdf). Maliheh Shirvanian, Stanislaw Jareckiy, Hugo Krawczykz. Nitesh Saxena. 10.1109/ICDCS.2017.64, 2017, 2017 IEEE 37th International Conference on Distributed Computing Systems (ICDCS).
- ["OPAQUE: An Asymmetric PAKE Protocol Secure Against Pre-Computation Attacks"](https://eprint.iacr.org/2018/163.pdf). Stanislaw Jarecki, Hugo Krawczyk, Jiayu Xu. 10.1007/978-3-319-78372-7_15, 2018, Advances in Cryptology – EUROCRYPT 2018, pp. 456-486.
- ["Simplified VSS and fast-track multiparty computations with applications to threshold cryptography"](http://www.eecs.harvard.edu/~cat/cs/tlc/papers/grr.pdf). Rosario Gennaro, Michael O. Rabin, Tal Rabin. 1998, PODC '98 Proceedings of the seventeenth annual ACM symposium on Principles of distributed computing, pp. 101-111.
- ["Share Conversion, Pseudorandom Secret-Sharing and Applications to Secure Computation"](http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.77.8491&rep=rep1&type=pdf). Ronald Cramer, Ivan Damgård, Yuval Ishai. TCC 2005. Lecture Notes in Computer Science, 2005, Kilian J. (eds) Theory of Cryptography., Vol. 3378.
- ["Generating hard instances of lattice problems"](https://pdfs.semanticscholar.org/f6db/df621b0acc9a131f7f2a4d3efbd4bfb0db58.pdf). Ajtai, M. ISBN:0-89791-785-5, 1996, STOC '96 Proceedings of the twenty-eighth annual ACM symposium on Theory of computing, pp. 99-108.
- ["Towards quantum-resistant cryptosystems from supersingular elliptic curve isogenies"](https://eprint.iacr.org/2011/506.pdf). David Jao, Luca De Feo. ISBN: 978-3-642-25404-8, 2011, PQCrypto'11 Proceedings of the 4th international conference on Post-Quantum Cryptography, pp. 19-34.
- ["Efficient, robust and constant-round distributed RSA key generation"](https://www.iacr.org/archive/tcc2010/59780180/59780180.pdf). Ivan Damgård, Gert Læssøe Mikkelsen. ISBN:3-642-11798-8 978-3-642-11798-5, 2010, TCC'10 Proceedings of the 7th international conference on Theory of Cryptography, pp. 183-200.
- ["Short Signatures from the Weil Pairing"](https://www.iacr.org/archive/asiacrypt2001/22480516.pdf). Dan Boneh, Ben Lynn, Hovav Shacham. 2001, In Proceedings of the 7th International Conference on the Theory and Application of Cryptology and Information Security: Advances in Cryptology (ASIACRYPT '01), Colin Boyd (Ed.), pp. Springer-Verlag, Berlin, Heidelberg, 514-532.
- ["The pythia PRF service"](https://eprint.iacr.org/2015/644.pdf). Adam Everspaugh, Rahul Chatterjee, Samuel Scott, Ari Juels, Thomas Ristenpart. ISBN: 978-1-931971-232, 2015, Proceeding SEC'15 Proceedings of the 24th USENIX Conference on Security Symposium, pp. 547-562.
- ["Identity-Based Encryption from the Weil Pairing. Dan Boneh"](https://crypto.stanford.edu/~dabo/papers/bfibe.pdf). Matthew K. Franklin. ISBN:3-540-42456-3, 2001, CRYPTO '01 Proceedings of the 21st Annual International Cryptology Conference on Advances in Cryptology, pp. 213-229.
- ["Fail-aware untrusted storage"](http://webee.technion.ac.il/~idish/ftp/faust-dsn09.pdf). Christian Cachin, Idit Keidar, Alexander Shraer. 2011, SIAM Journal on Computing, Vols. 40(2):493-533, April 2011.
- ["Beyond one-third faulty replicas in byzantine fault tolerant systems"](http://www.scs.stanford.edu/~jinyuan/bft2f.pdf). Jinyuan Li, David Maziéres. 2007, NSDI'07 Proceedings of the 4th USENIX conference on Networked systems design & implementation, pp. 10-10.

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

- [BFT-SMaRt Library](https://github.com/bft-smart/library)
- [Thunderella](https://eprint.iacr.org/2017/913.pdf)
- https://crysp.uwaterloo.ca/software/DKG/
- https://github.com/helium/erlang-dkg
- [Distributed Privacy Guard](http://nongnu.org/dkgpg/)
- [Vanish](http://vanish.cs.washington.edu/pubs/usenixsec09-geambasu.pdf)
- https://gitlab.com/neucrypt/mpecdsa
