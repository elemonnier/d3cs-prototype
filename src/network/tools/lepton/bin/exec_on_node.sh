#! /bin/bash

#  Execute a command related to an emulated node on a single host

#---------------------------------------------------------------------
#  Utility functions and base variables
#---------------------------------------------------------------------
#  Initialize the base directories
script_dir=$(dirname $0)
lepton_home=$(realpath ${script_dir}/..)

#  Load basic utility functions
. ${script_dir}/util/conf_functions.sh
. ${script_dir}/util/start_functions.sh
. ${script_dir}/util/oppnet_adapter.sh


#---------------------------------------------------------------------
#  Help: -h option
#---------------------------------------------------------------------
if (( $# > 0 )) && [ "$1" == "-h" ]; then
    echo ""
    echo "Execute a command related to an emulated node"
    echo ""
    echo "Arguments: <node_id> <command_with_args>\""
    echo "    <node_id>         the id of the node"
    echo "    <command_with_args> the command to be executed"
    echo ""
    exit -1
fi

node_id=$1
shift
command="$*"

#---------------------------------------------------------------------
#  Configuration 
#---------------------------------------------------------------------
#  Load the configuration properties
load_saved_config $*

#  check node_id
if [ "${node_id}" == "" ]; then
    echo "Unable to start the node."
    echo "The \"node_id\" property is missing."
    exit -1
fi

#  load the functions to start the lepton daemon and the emulated nodes
if [ "${oppnet_adapter}" != "" ] && [ -f ${oppnet_adapter} ]; then
    . ${oppnet_adapter}
    command -v exec_on_node >/dev/null 2>&1 || {
	echo "Unable to execute the command ${command}."
	echo "The \"exec_on_node\" function is missing in ${oppnet_adapter}"
	exit -1
    }
else
    echo "Unable to execute the command ${command}."
    echo "The \"oppnet_adapter\" property is missing."
    exit -1    
fi


#---------------------------------------------------------------------
#  Execute command
#---------------------------------------------------------------------
#  Call the exec function
#echo "Executing on ${node_id}: ${command}."
#echo "Redirecting outputs to ${log_dir}/${node_id}.out and ${log_dir}/${node_id}.err"
exec_on_node ${command} # > ${log_dir}/${node_id}.out 2>  ${log_dir}/${node_id}.err 
