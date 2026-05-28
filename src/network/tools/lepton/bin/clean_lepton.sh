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
    echo "Stop all lepton running processes and clear the logs directory"
    echo ""
    echo "Optional arguments:"
    echo "    [log_dir=<path/to/logs_directory>] the logs directory"
    echo "    [oppnet_adapter=<a_bash_script>]   the emulated platform script"
    echo ""
    exit -1
fi


#---------------------------------------------------------------------
#  Stop LEPTON
#---------------------------------------------------------------------
${script_dir}/stop_lepton.sh -f

#---------------------------------------------------------------------
#  Clear the logs directory
#---------------------------------------------------------------------
if [ "${log_dir}" != "" ] && [ -d ${log_dir} ]; then
    echo "Clear the log directory \"${log_dir}\""
    rm -rf ${log_dir}
fi
