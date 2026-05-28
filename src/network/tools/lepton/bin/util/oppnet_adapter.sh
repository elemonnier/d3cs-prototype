#! /bin/bash

#  Functions that should be provided by middleware systems to start
#  LEPTON and emulated nodes

#---------------------------------------------------------------------
#  Variables
#---------------------------------------------------------------------
#  Tags identifying the LEPTON process and a node process
lepton_process_tag="casa.lepton.leptond"
# node_process_tag=

# OppNetAdapter class name and classpath
oppnet_adapter_classname=
oppnet_adapter_classpath=

#---------------------------------------------------------------------
#  Start the LEPTON daemon
#
#  Arguments: [info] [conf=confFile]* [key=value]*
#
#---------------------------------------------------------------------
start_lepton() {
    
    #  Initialize the JVM options and Java system properties
    jvm_opts="-DHOME=${HOME} -DUSER=${USER} -DHOSTNAME=$(hostname)"
    jvm_opts="-XX:+UseG1GC -Xms32m -Xmx256m ${jvm_opts}"

    #  Start LEPTON
#    echo  "[$(date +%s)] Start LEPTON at ${start_time}"
    java ${jvm_opts} -cp $(make_lepton_classpath) casa.lepton.leptond "$@" 
}

#---------------------------------------------------------------------
#  Start an emulated node
#
#  node_id        : the id of the node
#  node_start_time: the time when the node should start (EPOCH in ms)
#  node_end_time  : the time when the node should stop, (EPOCH in ms)
#  node_seed      : seed value for the node's random generator
#  lepton_host    : name or address of the host that runs LEPTON
#  lepton_hub_port: TCP port number LEPTON's hub is listening to
#---------------------------------------------------------------------
#start_node() {
#
#     TO BE DEFINED FOR EACH TYPE OF OPPNET SYSTEM
#
#}

#---------------------------------------------------------------------
#  Stop an emulated node
#
#  node_id: the id of the node
#---------------------------------------------------------------------
#stop_node() {
#
#     TO BE DEFINED FOR EACH TYPE OF OPPNET SYSTEM
#
#}

#---------------------------------------------------------------------
#  Exec command on an emulated node
#
#  node_id: the id of the node
#  "$@"   : command (with arguments) to be executed on that node
#---------------------------------------------------------------------
#exec_on_node() {
#
#     TO BE DEFINED FOR EACH TYPE OF OPPNET SYSTEM
#
#}
