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
. ${script_dir}/util/oppnet_adapter.sh


#---------------------------------------------------------------------
#  Help: -h option
#---------------------------------------------------------------------
if (( $# > 0 )) && [ "$1" == "-h" ]; then
    echo ""
    echo "Show the lepton running processes status"
    echo ""
    echo "Optional arguments:"
    echo "    [log_dir=<path/to/logs_directory>] the logs directory"
    echo "    [oppnet_adapter=<a_bash_script>]   the emulated platform script"
    echo ""
    exit -1
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
#  Show LEPTON processes
#---------------------------------------------------------------------
#  Show the nodes processes
if [ "${node_process_tag}" != "" ]; then
    pids=$(ps aux | grep ${node_process_tag} | grep -v grep | awk '{print $2}' | wc -w)
    if (( ${pids} > 1 )); then
	echo "${pids} node processes running"
    elif (( ${pids} > 0 )); then
	echo "${pids} node process running"
    else
	echo "No node process running"
    fi
fi

#  Show the LEPTON process
if [ "${lepton_process_tag}" != "" ]; then
    pids=$(ps aux | grep ${lepton_process_tag} | grep -v grep | awk '{print $2}' | wc -w)
    if (( ${pids} > 1 )); then
	echo "${pids} LEPTON processes running"
    elif (( ${pids} > 0 )); then
	echo "${pids} LEPTON process running"
    else
	echo "No LEPTON process running"
    fi
fi
