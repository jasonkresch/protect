#!/bin/sh
export KEY_DIR="config/client/keys/"
java -classpath ../pross-server/target/pross-server-1.0-SNAPSHOT.jar com.ibm.pross.server.app.KeyGeneratorCli $KEY_DIR $1
