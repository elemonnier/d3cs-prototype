#! /bin/bash

#  Functions used by the cluster.sh script

#---------------------------------------------------------------------
#  Display the number of instances of LEPTON and emulated nodes running
#  on each host ($lepton_host and $nodes_hosts)
#  ---------------------------------------------------------------------
display_status() {

    #  load the functions to start the lepton daemon and the emulated nodes
    if [ "${oppnet_adapter}" != "" ] && [ -f ${oppnet_adapter} ]; then
	. ${oppnet_adapter}
    fi

    if [ "${lepton_process_tag}" != "" ]; then
	echo "Nb of LEPTON instances:"
	echo -n "   ${lepton_host}: "
	ssh ${lepton_host} "ps aux | grep ${lepton_process_tag} | grep -v grep" | wc -l
    fi
    if [ "${node_process_tag}" != "" ]; then
	echo "Nb of nodes instances:"
	for host in $(echo ${nodes_hosts} | sed 's/,/ /g'); do
	    echo -n "   ${host}: "
	    ssh ${host} "ps aux | grep ${node_process_tag} | grep -v grep" | wc -l
	done
    fi
}

#---------------------------------------------------------------------
#  Run a command on the hosts $lepton_host first and then $nodes_hosts
#---------------------------------------------------------------------
run_commands() {
    
    #  Initialize common variables
    nb_hosts=$(get_nb_hosts ${nodes_hosts})
    start_time=$(date +%s)
    remote_vars=""     # no system variables to be set before running cmd...
    remote_args="start_time=${start_time} nb_hosts=${nb_hosts}"
    
    #  Run lepton_host first
    num_host=$(get_num_host ${nodes_hosts} ${lepton_host})
    host=${lepton_host}
    run_command $* ${remote_args} num_host=${num_host} is_lepton_host=true

    #  Run nodes_hosts
    remote_args="${remote_args} is_lepton_host=false"
    num_host=0
    for host in $(echo ${nodes_hosts} | sed 's/,/ /g'); do
	if [ "${host}" != "${lepton_host}" ]; then
	    run_command $* ${remote_args} num_host=${num_host}
	fi
	num_host=$((${num_host}+1))
    done
}

#---------------------------------------------------------------------
#  Run a command on a remote host
#
#  host        : the target host
#  lepton_home : the target directory
#  remote_vars : the variables that should be set on $host before
#                running $cmd
#  cmd         : the command that will be started in $simul_dir
#                on $host
#---------------------------------------------------------------------
run_command() {

    # if [ "${host}" == "localhost" ] ||  [ "${host}" == "$(hostname)" ]; then
    # 	echo "cd ${lepton_home} ; ${remote_vars} ${cmd} $* &"
    # 	cd ${lepton_home} ; ${remote_vars} ${cmd} $* &
    # else
	echo "ssh  ${host} \"cd ${lepton_home} ; ${remote_vars} ${cmd} $* &\""
	ssh  ${host} "cd ${lepton_home} ; ${remote_vars} ${cmd} $* show=false &" & 
    # fi
    echo ""
}

#---------------------------------------------------------------------
#  Give the number of hosts in the ',' separated list of hosts $1
#---------------------------------------------------------------------
get_nb_hosts() {
    num_host=0
    for host in $(echo $1 | sed 's/,/ /g') ; do
	num_host=$((${num_host}+1))
    done
    echo ${num_host}
}


#---------------------------------------------------------------------
#  Give the index of the host $2 in the ',' separated list of hosts
#  $1 or -1 if the host is not in the list
#---------------------------------------------------------------------
get_num_host() {
    num_host=0
    for host in $(echo $1 | sed 's/,/ /g') ; do
	if [ "$2" == "${host}" ]; then
	    echo ${num_host}
	    return
	fi
	num_host=$((${num_host}+1))
    done
    echo -1
}

