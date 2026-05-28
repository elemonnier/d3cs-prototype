#!/bin/bash

src=/run/shm/${USER}/ibrdtn

if [ $# -lt 1 ] ; then
    cat <<EOF
Syntax: $0 start_time event_file

Blablabla.
EOF
    exit 1
fi

start_time=$1
evt_file=$2
dummy_msg=/run/shm/dummy_msg

if [ ! -e $dummy_msg ] ; then
    touch $dummy_msg
fi
    
grep " snd " $evt_file | while read time action sdr mid ; do
    mid=$(echo $mid | cut -d= -f2)
    abs_time=$(($start_time + $time))
    now=$(echo "scale=0; $(date +%s.%N) * 1000" | bc | cut -d. -f1)
    wait=$(($abs_time - $now))
    if [ $wait -gt 0 ] ; then
	wait=$(echo "scale=3; $wait / 1000" | bc)
	echo "Waiting until $time ($wait sec.)"
	sleep $wait
    fi
    lepton.sh exec $sdr send nobody $dummy_msg
done
