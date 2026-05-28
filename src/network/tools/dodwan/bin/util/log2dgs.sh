#!/bin/sh 

if [ $# -lt 1 ] ; then
  echo "log2dgs.sh <basetime> <period> <log file>"
  exit 0
fi

version=4.1

dir=$(realpath $(dirname $(realpath $0))/../..)

classpath="${dir}/libs/dodwan-${version}.jar"

java    -cp $classpath \
     	casa.dodwan.util.Log2DGS $*
