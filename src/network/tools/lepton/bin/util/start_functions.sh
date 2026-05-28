#! /bin/bash

#  Utility functions used by the start_lepton.sh script

#---------------------------------------------------------------------
#  Compute start and end steps for the lepton daemon and the nodes
#
#  Input:
#
#  duration       : the duration of the simulation (in s), or -1
#  time_margin    : how long we should start a node before it actually
#                   starts (in s)
#  jitter         : a jitter value for starting nodes (in s)
#  in_hist        : the name of the file that contains the nodes history
#  nodes          : the number of nodes or a ',' separated list of 'profile:nb'
#
#  Output:
#
#  start_time     : the time when lepton should run the 1st step (in ms)
#  nodes_hist     : (node_start_step,node_end_step,duration,node_id;)* with:
#      node_start_step : step when the node should be added (in ms)
#      node_end_step   : step when the node should be deleted (in ms), or -1
#      duration        : (node_end_step-node_start_step), or -1 (illimited)
#      node_id         : simple id or id:profile
#---------------------------------------------------------------------
compute_simul_history() {

    if [ "${hist}" == "" ]; then

        #  Set the hist variable to ensure this is done only once
        hist="true"

        #  Compute the history of the nodes
        if [ "${in_hist}" == "" ]; then     # no history
            if [ "${in_dgs}" == "" ]; then  # no DGS input file
                compute_nodes_history
            else                            # a DGS input file but no history
                hist="false"
            fi
        fi

        #  Initialize the start_time value to the current time (in s)
        start_time=$(date +%s)

        #  Compute the absolute lepton start time in ms
        start_time=$((${start_time}*1000))

        #  Add time_margin if it is defined
        if [ "${time_margin}" != "" ] && (( ${time_margin} > 0 )); then
            start_time=$((${time_margin}*1000+${start_time}))
        fi
    fi
}

#---------------------------------------------------------------------
#  Compute start and end steps for the nodes from the 'nodes'
#  property
#
#  Input:
#
#  duration       : the duration of the simulation (in s), or -1
#  jitter         : A jitter value for starting nodes (in s)
#  nodes          : The number of nodes or a ',' separated list of
#                   'profile:nb'
#
#  Output:
#
#  nodes_hist     : (node_start_step,node_end_step,duration,node_id;)* with:
#      node_start_step : step when the node should be added (in ms)
#      node_end_step   : step when the node should be deleted (in ms), or -1
#      duration        : (node_end_step-node_start_step), or -1 (illimited)
#      node_id         : simple id or id:profile
#---------------------------------------------------------------------
compute_nodes_history() {

    #  Compute the end_step in ms or -1 if no duration is defined
    end_step=-1
    if [ "${duration}" != "" ] && (( ${duration} > 0 )); then
        end_step=$((${duration}*1000))
    fi

    if [[ ${nodes} =~ ^[0-9]+$ ]]; then #  integer value (nb of nodes)

        nb_digits=${#nodes}
        if [ "${jitter}" != "" ] && (( ${jitter} > 0 )); then
            randoms=$(get_randoms ${nodes} 1000 ${seed})
        fi
        for (( num_node = 0; num_node < ${nodes}; num_node++ )); do
            node_id=$(create_node_ID ${num_node} ${nb_digits})
            nodes_hist="${nodes_hist}$(make_node_history);"
        done

    else                                #  ',' separated list 'nb:profile'

        nb=$(get_nb_nodes ${nodes})
        nb_digits=${#nb}
        num_node=0
        if [ "${jitter}" != "" ] && (( ${jitter} > 0 )); then
            randoms=$(get_randoms ${nb} 1000 ${seed})
        fi
        for token in $(echo ${nodes} | sed 's/,/ /g') ; do

            nb_nodes=$(echo ${token} | cut -d: -f2)
            node_profile=$(echo ${token} | cut -d: -f1)

            for (( i = 0; i < ${nb_nodes}; i++ )); do
                node_id=$(create_node_ID ${num_node} ${nb_digits} ${node_profile})
                nodes_hist="${nodes_hist}$(make_node_history);"
                num_node=$(($num_node+1))
            done
        done
    fi

    # sort the nodes history by start times
    sorted_nodes_hist="";
    for i in $(echo ${nodes_hist} | sed 's/;/\n/g' | sort -k1 -n); do
        sorted_nodes_hist="${sorted_nodes_hist};$i"
    done
    nodes_hist=${sorted_nodes_hist}
}

make_node_history() {
    node_start_step=$(get_random_delay)
    node_start_step=$((${node_start_step}+${nodes_deferred}*1000))
    node_duration=-1
    if (( ${end_step} > 0 )); then
        node_duration=$((${end_step}-${node_start_step}))
    fi
    echo "${node_start_step},${end_step},${node_duration},${node_id}"
}

#---------------------------------------------------------------------
#  Start the lepton daemon using the start_lepton function
#
#  Arguments: [info] [conf=confFile]* [key=value]*
#
#  Variables:
#
#  lepton_home  : the LEPTON install directory
#  log_dir      : the log directory where standard outputs are redirected
#---------------------------------------------------------------------
start_lepton_daemon() {

    #  Ensure that this host is supposed to run LEPTON
    if [ "${is_lepton_host}" == "true" ]; then

        if (( $# > 0 )) && [ "$1" == "info" ]; then

            #  List properties. No output redirection
            show_config
            start_lepton "$@"

        else

            #  Create the log directory if it does not exist
            if [ "${log_dir}" != "" ] && [ ! -d ${log_dir} ]; then
                mkdir -p ${log_dir}
            fi

            #  Information messages
            echo "Redirecting outputs to ${log_dir}/lepton.out and ${log_dir}/lepton.err"
            if [ "${out_dgs}" != "" ]; then
                echo "Writing the graph events to ${out_dgs}"
            fi

            #  Start the lepton daemon
            show_config > ${log_dir}/lepton.out
            start_lepton "$@" >> ${log_dir}/lepton.out 2>  ${log_dir}/lepton.err &
            lepton_pid=$!
            echo ${lepton_pid} > ${log_dir}/lepton-pid
        fi
    fi
}


#---------------------------------------------------------------------
#  Start the emulated nodes using the start_node function.
#
#  start_time     : The time when lepton should run the 1st step (in ms)
#  num_host       : index of the host where the script runs
#  nb_hosts       : the total number of hosts involved
#  time_margin    : how long we should start the node before it
#                   actually starts (in s)
#  nodes_hist     : (node_start_step,node_end_step,duration,node_id;)* with:
#      node_start_step : step when the node should be added (in ms)
#      node_end_step   : step when the node should be deleted (in ms), or -1
#      duration        : (node_end_step-node_start_step), or -1 (illimited)
#      node_id         : simple id or id:profile
#
#  $num_hosts and $nb_hosts allow to run concurrently on several hosts
#  (typically on a cluster). In that case each host will only create a
#  subset of the nodes (using a round-robin policy). If the simulation
#  is run on a single host, then $num_host=0 and $nb_hosts=1.
#---------------------------------------------------------------------
start_the_nodes() {

    num_node=0

    if [ "${nodes_hist}" != "" ]; then

        for node_hist in $(echo ${nodes_hist} | sed 's/;/ /g') ; do

            #  Ensure that this host is supposed to run this node
            if (( ${num_host} == $((${num_node} % ${nb_hosts})) )); then

                start_a_node "$@"
            fi

            num_node=$((${num_node}+1))
        done

    elif [ "${in_hist}" != "" ]; then

        grep -v "^#" ${in_hist} | tr -s ' ' | \
            while read line
        do

            #  Ensure that this host is supposed to run this node
            if (( ${num_host} == $((${num_node} % ${nb_hosts})) )); then

                node_hist=$(echo ${line} | sed 's/ /,/g')
                start_a_node "$@"
            fi

            num_node=$((${num_node}+1))
        done
    fi
}

#---------------------------------------------------------------------
#  Start a single emulated node using the start_node function.
#
#  start_time      : the time when the step 0 occurs (in ms)
#  node_hist       : node_start_step,node_end_step,node_duration,node_id
#  num_node        : index of the node to be started
#  time_margin     : how long we should start the node before it
#                    actually starts (in s)
#
#  Each application node is created a short while before it is
#  actually started, according to $node_start_time and $start_margin
#  arguments. Thus, if node N is supposed to run from time
#  $node_start_time, then the corresponding process is created at
#  ($node_start_time - $start_margin), and this process is passed
#  argument $node_start_time and $node_end_time so it can start and
#  stop at the appropriate times.
#---------------------------------------------------------------------
start_a_node() {

    #  Get the node start/end steps
    node_id=$(echo ${node_hist} | cut -d, -f4)
    node_start_step=$(echo ${node_hist} | cut -d, -f1)
    node_end_step=$(echo ${node_hist} | cut -d, -f2)

    #  Compute the node start/end times
    node_start_time=$((${start_time}+${node_start_step}))
    node_end_time=-1
    if ((${node_end_step} > 0)); then
        node_end_time=$((${start_time}+${node_end_step}))
    fi

    #  Compute the node seed
    node_seed=$((${seed}+${num_node}*1000))

    #  Defer start until (node_start_time - time_margin)
    sleep_time=$((${node_start_time}/1000-${time_margin:-0}-$(date +%s)))
    if (( ${sleep_time} > 0 )); then
        sleep ${sleep_time}
    fi

    #  Call the start_node function
    set_node_started ${node_id} true
    start_node "$@" > ${log_dir}/${node_id}.out 2>  ${log_dir}/${node_id}.err  &
}

#---------------------------------------------------------------------
#  Wait for the end of the lepton daemon, either by waiting for the
#  lepton-pid file to be deleted (through inotify-tools) or by
#  polling the current processes if the inotifywait command is not
#  available
#
#  Input:
#  log_dir         : the directory that contains the lepton-pid file
#  lepton_pid      : the process id of the lepton daemon
#---------------------------------------------------------------------
#wait_lepton_daemon() {
#
#    if [ -f ${log_dir}/lepton-pid ]; then
#	if command -v inotifywait >/dev/null 2>&1; then
#
#	    # waiting for the lepton-pid file to be deleted
#	    inotifywait -e delete ${log_dir}/lepton-pid >/dev/null 2>&1
#
#	elif [ ! -z ${lepton_pid} ]; then
#
#	    # polling processes
#	    echo "   inotifywait command not available. Polling..."
#	    while ps -p ${lepton_pid} > /dev/null; do
#    		sleep 3
#	    done
#	    rm -f ${log_dir}/lepton-pid
#	fi
#    fi
#}

#---------------------------------------------------------------------
# Start a process that will be in charge of running the application
# scenario
#
#  start_time     : The time when lepton should run the 1st step (in ms)
#  app_log_file   : event file describing the application scenario
#---------------------------------------------------------------------
start_application_scenario() {

    rm -f ${log_dir}/app-scenario.log
    ${script_dir}/util/run_application_scenario.sh \
        $start_time $app_log_file \
        >> ${log_dir}/app-scenario.log &
    pid=$!
    echo $pid > ${log_dir}/app-scenario.pid
    echo "Application scenario started (app-scenario.pid=$pid)"
}
