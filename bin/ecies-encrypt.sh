#!/bin/sh
java -classpath ../pross-client/target/pross-client-1.0-SNAPSHOT.jar com.ibm.pross.client.encryption.EciesEncryptionClient $1 $2 $3 $4 $5 $6
