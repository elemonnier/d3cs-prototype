#! /bin/bash

#  Start LEPTON and emulated nodes on a single host
#  Used as a standalone script or launched by lepton.sh

#---------------------------------------------------------------------
#  Utility functions and base variables
#---------------------------------------------------------------------
#  Initialize the base directories
script_dir=$(dirname $0)
lepton_home=$(realpath ${script_dir}/..)

#  Load basic utility functions
. ${script_dir}/util/conf_functions.sh
. ${script_dir}/util/start_functions.sh
. ${script_dir}/util/stop_functions.sh
. ${script_dir}/util/oppnet_adapter.sh


# kill all subprocesses when the script terminates
trap "exit" INT TERM ERR
trap "kill 0" EXIT

#---------------------------------------------------------------------
#  Help: -h option
#---------------------------------------------------------------------
if (( $# > 0 )) && [ "$1" == "-h" ]; then
    echo ""
    echo "Start several emulated nodes"
    echo ""
    echo "Arguments: nodes=<nb_nodes> oppnet_adapter=<a_bash_script>"
    echo "    <nb_nodes>       the number of nodes to be started"
    echo "    <a_bash_script>  the emulated platform script"
    echo ""
    exit -1
fi


#---------------------------------------------------------------------
#  Configuration
#---------------------------------------------------------------------
#  Load the configuration properties
if [[ "${LEPTON_VAR}" != "" ]]; then
    load_config "$@" log_dir=${LEPTON_VAR}
    echo "Using LEPTON_VAR: \"${LEPTON_VAR}\""
else
    load_config "$@"
    echo "No LEPTON_VAR set. Using \"${log_dir}\""
fi

#  load the functions to start the lepton daemon and the emulated nodes
if [ "${oppnet_adapter}" != "" ] && [ -f ${oppnet_adapter} ]; then
    . ${oppnet_adapter}
    command -v start_node >/dev/null 2>&1 || {
        echo "Unable to start the nodes."
        echo "The \"start_node\" function is missing in ${oppnet_adapter}"
        exit -1
    }
else
    echo "Unable to start the nodes."
    echo "The \"oppnet_adapter\" property is missing."
    exit -1
fi

#  Initialize the properties used to decide which nodes should run on
#  this host. Those properties are already initialized if this script
#  is launched by the 'cluster.sh' script
is_lepton_host=${is_lepton_host:-true}  #  is this host supposed to run lepton
num_host=${num_host:-0}                 #  the index of this host
nb_hosts=${nb_hosts:-1}                 #  the total number of hosts
lepton_host=${lepton_host:-${HOST}}     #  the name of the host running lepton

#---------------------------------------------------------------------
#  Start LEPTON
#---------------------------------------------------------------------

#  Compute the simulation history (if it has not already been done in
#  cluster.sh)
compute_simul_history

args="log_dir=${log_dir} lepton_home=${lepton_home} start_time=${start_time}"

if command -v start_node >/dev/null 2>&1; then

    args="${args} oppnet_adapter_classname=${oppnet_adapter_classname}"

    #  Start the emulated nodes
    if (( $# == 0 )) || [ "$1" != "info" ]; then
        if [ "${hist}" == "false" ]; then
            echo "History file does not exist. Unable to start emulated nodes"
        else
            start_the_nodes "$@" $args &
        fi
    fi

fi
