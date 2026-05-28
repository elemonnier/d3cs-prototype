#! /bin/bash

#  Entry point for all LEPTON commands. Uses the start_lepton.sh,
#  stop_lepton.sh and cluster.sh scripts that can also run in a
#  standalone way.

#---------------------------------------------------------------------
#  Base variables
#---------------------------------------------------------------------
#  Initialize the base directories
script_dir=$(dirname $0)
lepton_home=$(realpath ${script_dir}/..)


#---------------------------------------------------------------------
#  Help: -h option
#---------------------------------------------------------------------
usage() {
    echo ""
    echo "Usage: $0 <command> [option]*"
    # echo "Usage: $0 <command> [cluster] [option]*"
    echo ""
    echo "With command:"
    echo "    info|status|start|stop|clean|start_node|start_nodes|stop_node|status_node|exec"
    echo ""
    echo "To display help about the commands:   $0 -h <command>"
    # echo "To display help about the commands:   $0 -h <command> [cluster]"
    echo "           the default configuration: $0 -h info"
    echo ""
}


if (( $# > 0 )) && [ "$1" == "-h" ]; then

    if  (( $# > 1 )); then
	if (( $# > 2 )) && [ "$3" == "cluster" ]; then
	    cluster="true"
	fi
	case $2 in
	    info )
		if [ "$cluster" == "true" ]; then
		    ${lepton_home}/bin/cluster.sh -h info
		else
		    cat ${lepton_home}/conf/lepton.conf
		fi
		;;
	    start )
		if [ "$cluster" == "true" ]; then
		    ${lepton_home}/bin/cluster.sh -h start
		else
		    ${lepton_home}/bin/start_lepton.sh -h
		fi
		;;
	    stop )
		if [ "$cluster" == "true" ]; then
		    ${lepton_home}/bin/cluster.sh -h stop
		else
		    ${lepton_home}/bin/stop_lepton.sh -h
		fi
		;;
	    status )
		${lepton_home}/bin/status_lepton.sh -h
		;;
	    clean )
		${lepton_home}/bin/clean_lepton.sh -h
		;;
        start_nodes )
		${lepton_home}/bin/start_nodes.sh -h
		;;
	    start_node )
		${lepton_home}/bin/start_node.sh -h
		;;
	    stop_node )
		${lepton_home}/bin/stop_node.sh -h
		;;
	    status_node )
		${lepton_home}/bin/status_node.sh -h
		;;
	    exec )
		${lepton_home}/bin/exec_on_node.sh -h
		;;
	    * )
		usage
		;;
	esac

    else
	usage
    fi
    exit -1
fi

#---------------------------------------------------------------------
#  Main
#---------------------------------------------------------------------
command="start" # default value if no argument
if (( $# > 0 )); then
    command=$1
    shift 1
fi
if (( $# > 0 )) && [ "$1" == "cluster" ]; then
    cluster="true"
    shift 1
fi

case "${command}" in
    "info" )
	if [ "$cluster" == "true" ]; then
	    ${lepton_home}/bin/cluster.sh info "$@"
	else
	    ${lepton_home}/bin/start_lepton.sh info "$@"
	fi
	;;
    "start" )
	if [ "$cluster" == "true" ]; then
	    ${lepton_home}/bin/cluster.sh start "$@"
	else
	    ${lepton_home}/bin/start_lepton.sh "$@"
	fi
	;;
    "stop" )
	if [ "$cluster" == "true" ]; then
	    ${lepton_home}/bin/cluster.sh stop "$@"
	else
	    ${lepton_home}/bin/stop_lepton.sh "$@"
	fi
	;;
    "status" )
	${lepton_home}/bin/status_lepton.sh "$@"
	;;
    "clean" )
	${lepton_home}/bin/clean_lepton.sh "$@"
	;;
    "start_node" )
	${lepton_home}/bin/start_node.sh "$@"
	;;
    "start_nodes" )
	${lepton_home}/bin/start_nodes.sh "$@"
	;;
    "stop_node" )
	${lepton_home}/bin/stop_node.sh "$@"
	;;
    "status_node" )
	${lepton_home}/bin/status_node.sh "$@"
	;;
    "exec" )
	${lepton_home}/bin/exec_on_node.sh "$@"
	;;
    * )
	usage
	;;
esac
