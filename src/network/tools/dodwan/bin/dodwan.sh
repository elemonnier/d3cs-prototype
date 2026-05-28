#!/bin/bash

if [ -z $DODWAN_HOME ]; then
    echo "Error: \$DODWAN_HOME is not defined."
    exit
fi

. ${DODWAN_HOME}/bin/util/dodwan_functions.sh

# ------------------------------------------------------------
usage() {
    cat <<EOF

Usage: dodwan.sh start
               | stop
               | load
               | status
               | clear
               | publish <desc> <fname>
               | subscribe <key> <pattern> {-d dir | -e cmd}
               | unsubscribe <key>
               | console (for experts)

EOF
    exit 0
}

# ------------------------------------------------------------

if [ "$1" == "-h" ] ; then
    usage
fi

if [ -z $node_id ] ; then
    node_id=$HOSTNAME
    console_port=4000
fi

if [ -z "$init_cmd" ] ; then
    init_cmd="do tr add udp0 -t udp -ra 224.0.0.42 -rp 8500 -p 10 -use_tcp true"
fi

case $1 in
    start)
	start_node
	;;
    stop)
	stop_node
	;;
    status)
	status_node
	;;
    clear)
	clear
	;;
    console)
	console
	;;
    publish)
	if [ $# -lt 2 ] ; then
	    usage
	fi
	shift 
	publish $*
	;;
    subscribe)
	if [ $# -lt 2 ] ; then
	    usage
	fi
	shift
	subscribe $*
	;;
    unsubscribe)
	if [ $# -lt 1 ] ; then
	    usage
	fi
	shift
	unsubscribe $*
	;;
    load)
	load_libs
	;;
    *)
	usage
	;;
esac
