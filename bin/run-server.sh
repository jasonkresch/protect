#!/bin/sh
export CONF_DIR="config/server/"
java -classpath ../pross-server/target/pross-server-1.0-SNAPSHOT.jar com.ibm.pross.server.app.ServerApplication $CONF_DIR $1
