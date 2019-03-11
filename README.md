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

***PROTECT*** supports fine-grained user access controls. Each user can be granted any one of 10 defined permissions to each secret.  Access controls are defined in the config file `config/client/clients.config`.

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

Where SHAREHOLDER-i is the IP address of the shareholder with index = i.

#### Browser Interaction

Exploring system, servers, secrets, shares. (With read permission)
Configuring CA certificates (avoid SSL error).
Note: each server uses its own CA to issue its certificates.  These may be generated individually at each sever, then collected and distributed to all.  CA itself not checked, only used for client browsers. Servers' use direct Public key matching.

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

To obtain a sharing of a particular value, one can use the "shamir-share.py" script. The following command shows an example with number of shareholders = 5, reconstruction threshold = 3, and sharing the value "1000":

```
$ ./shamir-share.py 5 3 1000
```

Output:
```
Shares:
(1, 16780829942398145718766131207515104628060049441812475815286826296451235316215L)
(2, 69445721854271011972215100496134157649123142667565881836159569062930391762336L)
(3, 42202586525262349997649460916449585533192324453124457720195969238368957294994L)
(4, 50843513165728408557766659417868961810264550022623963809818285883835443958558L)
(5, 95368501775669187652566696000392286480339819376064400105026518999329851753028L)
Secret Public Key:
(11496013529637860221919730206355387223102005066697739921363561317831349586700, 76204896272524372731756530748799401765655575344541547788929707715182487989417)
```

One would then take each of those shares and store them directly to each server.

Alternatively, one can initiate the DKG immediately without pre-storing shares to create shares of a random secret.

In either case, to initiate the DKG and establish the secret click the "Initiate DKG" button.

**Video demonstration of generating a secret and self healing:**

[![Alt text](https://img.youtube.com/vi/ZMjMlC52MJc/0.jpg)](https://www.youtube.com/watch?v=ZMjMlC52MJc)

**Generate or Store page of PROTECT:**

![alt text](https://raw.githubusercontent.com/jasonkresch/protect/master/docs/screenshots/pre-dkg.png "Generate Secret")

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

#### Command Line Interction

All of the interactions that are possible through a web browser can be invoked via command line utilities such as "cURL".  This can be used to write automated scripts and applications. In addition, many of the APIs support a flag to return the output in *JSON*--a machine parsable format that simplifies processing of responses by applications.

##### Get Identity information via cURL

The following command is an examaple of obtaining the identity information from a ***PROTECT*** server running as shareholder with index 1 and authenticating as the user *administrator*:

```bash
$ curl --cacert config/ca/ca-cert-server-1.pem --cert config/client/certs/cert-administrator --key config/client/keys/private-cert-administrator https://localhost:8081/id
```

##### Store Share via cURL

There 

###### Store Elliptic Curve Share

###### Store RSA Share

##### Initiate DKG via cURL

##### Get Share information via cURL

##### Read Share via cURL

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

### Example Applications

**Video demonstration of using Encryption and Signing Clients:**

[![Alt text](https://img.youtube.com/vi/hVjxZmUPwlU/0.jpg)](https://www.youtube.com/watch?v=hVjxZmUPwlU)

#### Read / Write Client Utility

##### Storing a specific secret

*Required Permissions:* `STORE`

Must be done before DKG is performed. Must have store permission.

```
$ ./store-secret.sh config administrator prf-secret WRITE 312
```

##### Reading a stored secret

*Required Permissions:* `READ`

```
$ ./store-secret.sh config administrator prf-secret READ
```

#### RSA Signing Client

*Required Permissions:* `INFO` and `STORE` and `GENERATE`

##### Generating a new RSA Private Key

./threshold-ca.sh config signing_user rsa-secret GENERATE threshold-ca.pem "CN=threshold"
openssl x509 -text -noout -in threshold-ca.pem 

 (Note, no private key anywhere, it was thresholdized and stored to the servers as shares)  We leave the public key here to get the issuer name and also to double-check the resulting certificate's validity. Exists in RAM only, and only temporarily.

##### Issuing a Certificate with the RSA Private Key

*Required Permissions:* `INFO`, `SIGN`

```
$ openssl ecparam -name prime256v1 -genkey -noout -out priv-key.pem && openssl ec -in priv-key.pem -pubout -out pub-key.pem

$ ./threshold-ca.sh config signing_user rsa-secret ISSUE threshold-ca.pem pub-key.pem new-cert.pem "CN=example-entity" 
$ openssl verify -verbose -CAfile threshold-ca.pem new-cert.pem
$ openssl x509 -text -noout -in new-cert.pem
```

Must have read permission.

#### ECIES Decryption Client

##### Encrypting a File

*Required Permissions:* `INFO`, `EXPONENTIATE`

```
$ ./ecies-encrypt.sh config/ administrator prf-secret ENCRYPT secret.txt out.enc
```

Output:

```
```

##### Decrypting a File

*Required Permissions:* `INFO`, `EXPONENTIATE`

```
$ ./ecies-encrypt.sh config/ administrator prf-secret DECRYPT out.enc restored.txt
```

Output:

```
```


## Design

TODO: Include link to tunable Secrity eprint.

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
- TOPPSS
- UOKMS
- Other references from NIST submission
- Ford-Kaliski on password hardening
- NIST Draft on Threshold Security
- [Threshold Schemes for Cryptographic Primitives: Challenges and Opportunities in Standardization and Validation of Threshold Cryptography](https://csrc.nist.gov/publications/detail/nistir/8214/final)
https://www.nongnu.org/libtmcg/dg81_slides.pdf

TODO: Add References from NIST presentation proposal

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
- https://gitlab.com/neucrypt/mpecdsa
