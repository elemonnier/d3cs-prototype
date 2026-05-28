#! /bin/bash

#  Start an emulated node on a single host

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
    echo "Stop a single emulated node"
    echo ""
    echo "Arguments: node_id=<a_node_id> oppnet_adapter=<a_bash_script>"
    echo "    <a_node_id>      the id of the node"
    echo "    <a_bash_script>  the emulated platform script"
    echo ""
    exit -1
fi


#---------------------------------------------------------------------
#  Configuration 
#---------------------------------------------------------------------
#  Load the configuration properties
load_saved_config $*

#  check node_id
if [ "${node_id}" == "" ]; then
    echo "Unable to stop the node."
    echo "The \"node_id\" property is missing."
    exit -1
fi

#  load the functions to start the lepton daemon and the emulated nodes
if [ "${oppnet_adapter}" != "" ] && [ -f ${oppnet_adapter} ]; then
    . ${oppnet_adapter}
    command -v stop_node >/dev/null 2>&1 || {
	echo "Unable to stop the node ${node_id}."
	echo "The \"stop_node\" function is missing in ${oppnet_adapter}"
	exit -1
    }
else
    echo "Unable to stop the node ${node_id}."
    echo "The \"oppnet_adapter\" property is missing."
    exit -1    
fi


#---------------------------------------------------------------------
#  Stop the node
#---------------------------------------------------------------------

#  Call the start_node function
echo "Stopping the node ${node_id}."
set_node_started ${node_id} false
stop_node > ${log_dir}/${node_id}.out 2>  ${log_dir}/${node_id}.err 
