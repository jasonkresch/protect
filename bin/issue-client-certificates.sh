#!/bin/sh
export CA_DIR="config/ca/"
export KEY_DIR="config/client/keys/"
export CERT_DIR="config/client/certs/"
java -classpath ../pross-server/target/pross-server-1.0-SNAPSHOT.jar com.ibm.pross.server.app.CertificateAuthorityCli $CA_DIR $KEY_DIR $CERT_DIR false
