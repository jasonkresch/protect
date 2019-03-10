#!/bin/sh
export CONF_DIR="config/server/"
export SERVER_CMD="java -classpath ../pross-server/target/pross-server-1.0-SNAPSHOT.jar com.ibm.pross.server.app.ServerApplication $CONF_DIR"

i=1
while [ "$i" -le "$1" ]; do
  echo "Starting PROTECT server $i"
  $SERVER_CMD $i >> "/tmp/protect-server-$i.log" &
  pid=$!
  echo "  PROTECT Server-$i started [pid = $pid], writing output to /tmp/protect-server-$i.log" 
  echo "  Writing PROTECT Server-$i pid to /tmp/protect-server-$i.pid"
  echo "$pid" > "/tmp/protect-server-$i.pid"
  i=$(($i + 1))
done
