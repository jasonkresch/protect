#!/bin/sh

i=1
while [ "$i" -le "$1" ]; do
  pid=$(cat "/tmp/protect-server-$i.pid")
  echo "Sending kill to PROTECT server $i [pid = $pid]"
  kill $pid
  i=$(($i + 1))
done
