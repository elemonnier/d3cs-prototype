#!/bin/sh 

if [ $# -lt 1 ] ; then
  echo "log2msg.sh <basetime> <log file>"
  exit 0
fi

version=3.2

classpath="libs/dodwan-${version}.jar"

java    -cp $classpath \
     	casa.dodwan.util.Log2Msg $*
