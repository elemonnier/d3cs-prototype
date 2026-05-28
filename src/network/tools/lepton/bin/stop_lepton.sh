#!/bin/bash

#  Stop LEPTON and emulated nodes on a single host
#  Used as a standalone script or launched by lepton.sh

#---------------------------------------------------------------------
#  Utility functions and base variables
#---------------------------------------------------------------------
#  Initialize the base directories
script_dir=$(dirname $0)
lepton_home=$(realpath ${script_dir}/..)

#  Load basic utility functions
. ${script_dir}/util/conf_functions.sh
. ${script_dir}/util/stop_functions.sh
. ${script_dir}/util/oppnet_adapter.sh


#---------------------------------------------------------------------
#  Help: -h option
#---------------------------------------------------------------------
if (( $# > 0 )) && [ "$1" == "-h" ]; then
    echo ""
    echo "Stop all lepton running processes"
    echo ""
    echo "Optional arguments:"
    echo "    [-f]                               force"
    echo "    [log_dir=<path/to/logs_directory>] the logs directory"
    echo "    [oppnet_adapter=<a_bash_script>]   the emulated platform script"
    echo ""
    exit -1
fi

#---------------------------------------------------------------------
#  -f option
#---------------------------------------------------------------------
if (( $# > 0 )) && [ "$1" == "-f" ]; then
    force="-9"
    shift
fi

#---------------------------------------------------------------------
#  Configuration
#---------------------------------------------------------------------
#  Load the configuration properties
load_saved_config $*

#  load the variables to stop the lepton daemon and the emulated nodes
if [ "${oppnet_adapter}" != "" ] && [ -f ${oppnet_adapter} ]; then
    . ${oppnet_adapter}
fi


#---------------------------------------------------------------------
#  Stop LEPTON
#---------------------------------------------------------------------
#  Stop the node processes
stop_nodes

#  Stop the lepton process
stop_lepton_daemon
