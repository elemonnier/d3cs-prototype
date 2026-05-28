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
    java $JAVA_OPTS -cp $(make_lepton_classpath) casa.lepton.leptond -h
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

#  Load the functions to start the lepton daemon and the emulated nodes
if [ "${oppnet_adapter}" != "" ] && [ -f ${oppnet_adapter} ]; then
    . ${oppnet_adapter}
fi

#  Check that no LEPTON instance is running before starting a new one
if [ "$1" != "info" ]; then
    pids=$(ps aux | grep ${lepton_process_tag} | grep -v grep | awk '{print $2}' | wc -w)
    if (( ${pids} > 0 )); then
	echo "A LEPTON instance seems to be running. Stop this instance before starting a new one"
	exit -1
    fi
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

#  Store actual args to the log directory
if [ "$1" != "info" ]; then
    mkdir -p ${log_dir}
    echo "$@" > ${log_dir}/.config
fi

args="log_dir=${log_dir} lepton_home=${lepton_home} start_time=${start_time}"

# The shell scripts source conf/lepton.conf directly, while the Java daemon
# also loads its packaged defaults. Forward the values that must stay aligned.
for key in nodes duration in_dgs node_labels nodes_profiles range connectivity_profiles default_connectivity_type; do
    value=$(eval "printf '%s' \"\${${key}}\"")
    if [ "${value}" != "" ]; then
        args="${args} ${key}=${value}"
    fi
done

if command -v start_node >/dev/null 2>&1; then

    #  Start the lepton daemon that should not start simulated nodes
    args="${args} oppnet_adapter_classname=${oppnet_adapter_classname}"
    start_lepton_daemon "$@" $args accel=1 in_hist= nodes_hist=

    # Start the application scenario (if required)
    if [ x$run_app_scenario == xtrue ] ; then
	if [ -z $app_log_file ] ; then
	    echo "WARNING: \$app_log_file is not defined"
	else
	    start_application_scenario &
	fi
    fi

    #  Start the emulated nodes
    if (( $# == 0 )) || [ "$1" != "info" ]; then
	if [ "${hist}" == "false" ]; then
	    echo "History file does not exist. Unable to start emulated nodes"
	else
	    start_the_nodes "$@" $args &
	fi
    fi

else
    #  Start the lepton daemon that should start simulated nodes
    start_lepton_daemon "$@" $args nodes_hist=${nodes_hist}
fi

# wait for the lepton daemon end
echo "Waiting for the lepton daemon termination (lepton_pid=$lepton_pid)"
wait $lepton_pid

#wait_lepton_daemon 2>/dev/null

#  Lepton daemon closed. Stop the node processes
echo "Lepton stopped. Stopping nodes"
stop_nodes

# Stop the application scenario (if any)
#if [ x$run_app_scenario == xtrue ] ; then
#  if [ -z $app_log_file ] ; then
#      stop_application_scenario
#  fi
#fi
