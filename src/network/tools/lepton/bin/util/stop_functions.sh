#! /bin/bash

#  Utility functions used by the stop_lepton.sh script

#---------------------------------------------------------------------
#  Compute a list of nodes either from an history file or the nodes
#  variable
#
#  Input:
#  in_hist        : the name of the file that contains the nodes history
#  nodes          : the number of nodes or a ',' separated list of 'profile:nb'
#
#  Output:
#
#  nodes_list     : ' ' separated list of 'node_id'
#---------------------------------------------------------------------
compute_nodes_list() {

    if [ "${in_hist}" != "" ]; then     # history file

	nodes_list=$(grep -v "^#" ${in_hist} | sed 's/\t/ /g' | tr -s ' ' | cut -d" " -f4)

    else

	if [[ ${nodes} =~ ^[0-9]+$ ]]; then #  integer value (nb of nodes)
	    nb=${nodes}
	else                                #  ',' separated list 'nb:profile'
	    nb=$(get_nb_nodes ${nodes})
	fi

	nb_digits=${#nb}
	for (( num_node = 0; num_node < ${nb}; num_node++ )); do
	    node_id=$(create_node_ID ${num_node} ${nb_digits})
	    nodes_list="${nodes_list} ${node_id}"
	done

    fi
}

#---------------------------------------------------------------------
#  Stop the lepton daemon
#
#  Input:
#  log_dir              : the directory that contains the lepton-pid file
#  lepton_process_tag   : tag identifying the LEPTON process
#  force                : '-9' to force killing the process
#---------------------------------------------------------------------
stop_lepton_daemon() {

    killed="false"

    if [ -f ${log_dir}/lepton-pid ]; then

        # stop the process whose pid is in the lepton-pid file
        lepton_pid=$(cat ${log_dir}/lepton-pid)
        if ps -p ${lepton_pid} > /dev/null; then
            echo "Stopping the lepton process ${lepton_pid}"
            kill ${force} ${lepton_pid}
            killed="true"
        fi
        rm -f ${log_dir}/lepton-pid

    fi

    if [ "${lepton_process_tag}" != "" ]; then

        # stop the processes that match lepton_process_tag
        pids=$(ps aux | grep ${lepton_process_tag} | grep -v grep | awk '{print $2}')
        if [ "${pids}" != "" ]; then
            for pid in ${pids}; do
                echo "Stopping the lepton process ${pid}"
                kill ${force} ${pid} 2> /dev/null
                killed="true"
            done
        fi
    fi

    if [ "${killed}" == "false" ]; then
        echo "No lepton process"
    fi
}

#---------------------------------------------------------------------
#  Stop the nodes processes either using the oppnet-adapter stop_node
#  function or a tag identifying the node processes
#
#  Input:
#  log_dir              : the directory that contains the .nodes directory
#  node_process_tag     : tag identifying the node process
#  force                : '-9' to force killing the process
#---------------------------------------------------------------------
stop_nodes() {

    killed="false"

    if command -v stop_node >/dev/null 2>&1; then

        if [ -d ${log_dir}/.nodes ]; then

            for node_id in $(ls ${log_dir}/.nodes); do
                set_node_started ${node_id} false
                stop_node ${node_id}
                killed="true"
            done

        else

            compute_nodes_list
            for node_id in ${nodes_list}; do
                set_node_started ${node_id} false
                stop_node ${node_id}
                killed="true"
            done

        fi

    elif [ "${node_process_tag}" != "" ]; then

        pids=$(ps aux | grep ${node_process_tag} | grep -v grep | awk '{print $2}')
        if [ "${pids}" != "" ]; then
            for pid in ${pids}; do
                echo "Stopping the node process ${pid}"
                kill ${force} ${pid} 2> /dev/null
                killed="true"
            done
        fi
    fi

    if [ "${killed}" == "false" ]; then
        echo "No node process"
    fi
}

#---------------------------------------------------------------------
#  Stop the process that runs the application scenario
#
#  Input:
#  log_dir     : the directory that contains the app-scenario.pid file
#  force       : '-9' to force killing the process
#---------------------------------------------------------------------
#stop_application_scenario() {
#
#    if [ -f ${log_dir}/app-scenario.pid ]; then
#
#	# stop the process whose pid is in the app-scenario.pid file
#	app_pid=$(cat ${log_dir}/app-scenario.pid)
#	if ps -p ${app_pid} > /dev/null; then
#	    echo "Stopping the application scenario process ${app_pid}"
#	    kill ${force} ${app_pid} 2> /dev/null
#	fi
#	rm -f ${log_dir}/app-scenario.pid
#
#    fi
#}
