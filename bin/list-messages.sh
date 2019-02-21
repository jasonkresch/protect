#!/bin/sh
export MESSAGE_DIR="config/server/state/"
java -classpath ../pross-server/target/pross-server-1.0-SNAPSHOT.jar com.ibm.pross.server.app.MessageStatusCli $MESSAGE_DIR $1
