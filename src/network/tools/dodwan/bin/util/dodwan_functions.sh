#!/bin/bash

if [ -z $DODWAN_HOME ]; then
    echo "Error: \$DODWAN_HOME is not defined."
    exit
fi

#---------------------------------------------------------------------
#  Download the necessary external jars for all the plugins
#---------------------------------------------------------------------
load_libs() {
    shopt -s nullglob
    # DoDWAN libs
    echo "# Downloading external jars for DoDWAN..."
    pushd ${DODWAN_HOME}/libs > /dev/null
    wget -nc  -nv  -i dependencies
    popd > /dev/null
    # Plugin libs 
    pushd ${DODWAN_HOME}/plugins > /dev/null 
    for p in * ; do
	echo "# Downloading external jars for plugin" $p ...
	pushd $p > /dev/null
        wget -nc  -nv  -i dependencies
	popd > /dev/null
    done
    popd > /dev/null   
}

#---------------------------------------------------------------------
#  Make a classpath with all the jar files for DoDWAN and its plugins
#---------------------------------------------------------------------
make_dodwan_classpath() {
    shopt -s nullglob

    classpath=""
    
    for f in ${DODWAN_HOME}/libs/*.jar ; do
        classpath="${f}:${classpath}"
    done

    for p in ${dodwan_plugins//,/ } ; do	 
	for f in ${DODWAN_HOME}/plugins/${p}/*.jar ; do
           classpath="${f}:${classpath}"
        done
    done
    echo "${classpath}"    
}	       

# ------------------------------------------------------------
init() {

    dodwan_log_dir=/run/shm/${USER}/dodwan
    node_dir=${dodwan_log_dir}/var/node/${node_id}
    pid_file=${node_dir}/pid
    ports_file=${node_dir}/ports
    fifo_file=${node_dir}/in
    
    if [ -e $ports_file ] ;  then
	tmp=$(grep dodwan.console_port ${ports_file})
	cport=${tmp#*=}
    fi
}

# ------------------------------------------------------------
send_command() {

#    if [ ! -e ${fifo_file} ] ; then
#	echo "Error: file ${fifo_file} does not exist"
#	exit 1
#    fi
#    echo $* > ${fifo_file}

    if [ -z $cport ] ; then
	echo "Error: no console is available"
	exit 1
    fi
    echo $* | nc -q 1 localhost $cport | sed -e 's/^% //'
}

# ------------------------------------------------------------
console() {

    init

    check_running
    
    if [ -z $cport ] ; then
	echo "Error: no console is available"
	exit 1
    fi
    nc localhost $cport
}

# ------------------------------------------------------------
check_running() {
    
    if [ ! -e ${pid_file} ] ; then
	echo "Warning: it seems node ${node_id} is not running"
	return
    fi

    pid=$(cat $pid_file)
    kill -0 $pid
    res=$?
    if [ $res -eq 1 ] ; then
	echo "Error: node ${node_id} is not running"
	rm -f $pid_file
    fi
}

# ------------------------------------------------------------
start_node() {
    #
    #  Starts a DoDWAN node
    #
    #  Uses the following variables:
    #
    # start_time     : time when the simulation should start (1st step run by LEPTON)
    # node_id        : id of the node (required)
    # node_start_time: time when the node should start (EPOCH in ms, optional)
    # node_end_time  : time when the node should stop (EPOCH in ms, optional)
    # node_seed      : seed to be used by that node's random generator (optional)
    # jvm_opts       : options for the JVM (optional)
    # classpath      : class path for Java code
    # dodwan_log_dir : log directory (required)
    # console_port   : TCP port number to be used by the node's console (optional)

    echo Starting node $node_id
    
    init

    if [ -e ${pid_file} ] ; then
	pid=$(cat ${pid_file})
	kill -0 $pid
	res=$?
	if [ $res -eq 1 ] ; then
	    rm -f $pid_file
	else
	    echo "Error: node ${node_id} is already running (with pid ${pid})"
	    exit 1
	fi
    fi
    
    mkdir -p $node_dir

    console_port=0
    props="-Ddodwan.host=${node_id} -Ddodwan.directory=${node_dir} -Ddodwan.base=${dodwan_log_dir}/base -Dstart_time=${start_time}"
    if [ ! -z $console_port ] ;  then 
	props="$props -Ddodwan.console_port=${console_port}"
    fi
    if [ ! -z $dodwan_plugins ] ;  then
        props="$props -Ddodwan.plugins=${dodwan_plugins}"
    fi

    # ---- FG: Modif temporaire (et très moche !)
    # in_opts="-Ddodwan_broadcast.type=causal -Ddodwan_broadcast.mode=file -Ddodwan_broadcast.file=$in_aevt -Ddodwan_broadcast.lifetime=600000"
    #    plugins_options="-Ddodwan_napi_tcp.port=0 -Ddodwan_napi_ws.port=0 $bcast_options"
    dodwan_props=/run/shm/${USER}/dodwan_props
    if [ -e $dodwan_props ] ; then
	props="$props $(cat $dodwan_props)"
    fi
    # ---- FG
    
    opts=""
    if [ ! -z $node_start_time ] ;  then
	opts="$opts -begin $node_start_time"
    fi
    if [ ! -z $node_end_time ] ;  then
	opts="$opts -end $node_end_time"
    fi
    if [ ! -z $node_seed ] ;  then
	opts="$opts -seed $node_seed"
    fi

    
    # Passing initialization commands to this node
    if [ ! -z "$init_cmd" ] ; then
	echo $init_cmd > ${node_dir}/cmd
	opts="$opts -c ${node_dir}/cmd"
    fi

#    if [ ! -e ${fifo_file} ] ; then
#	mkfifo ${fifo_file}
#    fi
#    opts="$opts -i ${fifo_file}"

    # Starting DoDWAN node
    #    java -Xms4m -Xmx4m \
	echo java ${jvm_opts} ${props} \
	 -cp $(make_dodwan_classpath) \
	 casa.dodwan.run.dodwand ${opts}
    java ${jvm_opts} ${props} \
	 -cp $(make_dodwan_classpath) \
	 casa.dodwan.run.dodwand ${opts} \
	 >> ${node_dir}/out 2>&1 &
    echo $! > ${pid_file}
    
}

# ------------------------------------------------------------
stop_node() {
    #
    #  Stops a DoDWAN node
    #
    #  Uses the following variables:
    #
    # node_id      : id of the node (required)

    echo Stopping node $node_id
    
    init

    check_running

    if [ -e $pid_file ] ; then
	pid=$(cat $pid_file)
	kill $pid >& /dev/null
	#    rm -f $pid_file $cport_file
    fi
}

# ------------------------------------------------------------
status_node() {
    #
    # Shows the status of DoDWAN (i.e. running or not running)
    #
    # node_id: id of the node (required)

    init

    if [ ! -e ${pid_file} ] ; then
	echo "Node ${node_id} is not running"
	return
    fi

    check_running
    echo "Node ${node_id} is running"
}

# ------------------------------------------------------------
clear() {
    #
    # Flushes the cache of DoDWAN
    #
    # node_id: id of the node (required)

    init

    if [ -e ${pid_file} ] ; then
	send_command "do ca cl"
    else
	rm -Rf ${node_dir}/cache/*
    fi
}

# ------------------------------------------------------------
publish() {
    #
    # Publish a message, with a file as its payload
    #
    # node_id: id of the node (required)
    # $1     : desc (comma-separated list of name=value pairs)
    # $2     : fname (file to be published)

    desc=$1
    fname=$2
    
    init

    check_running

    if [ ! -e $fname ] ; then
	echo "Error: file $fname does not exist"
	exit 1
    fi

    send_command "do ps p -desc \"src=${node_id},${desc}\" -f $fname"
}

# ------------------------------------------------------------
subscribe() {
    #
    # Sets a subscription
    #
    # node_id: id of the node (required)
    # $1     : key (used to unsubscribe)
    # $2     : pattern (comma-separated list of name=value pairs)
    # $3-*   : options (e.g., -d <dir> | -e <cmd>)

    key=$1
    pattern=$2
    shift 2
    options=$*

    init

    check_running

    send_command "do ps add -k ${key} -desc \"${pattern}\" ${options}"
}

# ------------------------------------------------------------
unsubscribe() {
    #
    # Remove subscriptions
    #
    # node_id: id of the node (required)
    # keys   : keys of the subscriptions to be removed

    keys=$*
    
    init

    check_running

    send_command "do ps rem ${keys}"
}
