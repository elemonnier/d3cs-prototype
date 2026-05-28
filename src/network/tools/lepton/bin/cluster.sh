#! /bin/bash

#  Start/stop LEPTON and emulated nodes on multiple hosts Used as a
#  standalone script or launched by lepton.sh Use the start_lepton.sh
#  and stop_lepton.sh scripts to start/stop LEPTON and emulated nodes
#  on each host.

#---------------------------------------------------------------------
#  Utility functions and base variables
#---------------------------------------------------------------------
#  Initialize the base directories
script_dir=$(dirname $0)
lepton_home=$(realpath ${script_dir}/..)

#  Load basic utility functions
. ${script_dir}/util/conf_functions.sh
. ${script_dir}/util/cluster_functions.sh
. ${script_dir}/util/start_functions.sh


#---------------------------------------------------------------------
#  Help: -h option
#---------------------------------------------------------------------
usage() {
    cluster_options="lepton_host=host nodes_hosts=host[,host]*"
    option1_details="lepton_host    the host that runs the lepton daemon"
    option2_details="nodes_hosts    the hosts that run the emulated nodes (',' separated list)"
    echo ""
    case "$1" in
	"start" )
	    echo "Run the LEPTON daemon and emulated nodes on multiple hosts..."
	    echo ""
	    echo "Arguments: ${cluster_options} [conf=confFile]* [key=value]*"
	    echo "    ${option1_details}"
	    echo "    ${option2_details}"
	    echo "    conf=confFile  configuration file defining some properties"
	    echo "    key=value      a configuration property"
	    ;;
	"stop" )
	    echo "Stop the LEPTON daemon and emulated nodes on multiple hosts..."
	    echo ""
	    echo "Arguments: ${cluster_options}"
	    echo "    ${option1_details}"
	    echo "    ${option2_details}"
	    ;;
	"info" )
	    echo "Display the number of instances of LEPTON and emulated nodes running on each host"
	    echo ""
	    echo "Arguments: ${cluster_options}"
	    echo "    ${option1_details}"
	    echo "    ${option2_details}"
	    ;;
	* )
	    echo "Usage: $0 start|stop|info [option]*"
	    echo ""
	    echo "To display help about the commands:   $0 -h start|stop|info"
    esac
    echo ""
    exit -1
}

if (( $# == 0 )); then
    usage help
    
elif [ "$1" == "-h" ]; then
    
    if (( $# == 1 )); then
	usage  help
    else
	usage "$2"
    fi
fi


#---------------------------------------------------------------------
#  Configuration
#---------------------------------------------------------------------
#  Load the configuration properties
load_config $*

#  Check the configuration properties 
if [ "${lepton_host}" == "" ] || [ "${nodes_hosts}" == "" ]; then
    echo "The 'lepton_host' and 'nodes_hosts' variables must be defined."
    exit -1
fi

#---------------------------------------------------------------------
#  Start LEPTON
#---------------------------------------------------------------------
#  Run remote commands
case "$1" in
    "start" )
	compute_simul_history
	cmd="bin/start_lepton.sh"
	shift 1
	run_commands $*
	;;
    "stop" )
	cmd="bin/stop_lepton.sh"
	shift 1
	run_commands $*
	;;
    "info" )
	display_status
	;;
    * )
	usage
	;;
esac
