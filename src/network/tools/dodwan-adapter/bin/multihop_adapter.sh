#!/bin/bash

if [ -z $DODWAN_HOME ]; then
    echo "Error: \$DODWAN_HOME is not defined."
    exit
fi

if [ -z $DODWAN_ADAPTER_HOME ]; then
    echo "Error: \$DODWAN_ADAPTER_HOME is not defined."
    exit
fi

# ------------------------------------------------------------
# Define where to find Java code
dodwan_classpath="${DODWAN_HOME}/libs/dodwan-4.1.jar"
adapter_classpath="${DODWAN_ADAPTER_HOME}/libs/dodwan-adapter-1.0.jar"

# ------------------------------------------------------------
# Variables used by LEPTON
# ------------------------------------------------------------

oppnet_adapter_classname=casa.lepton.hub.DodwanAdapter
oppnet_adapter_classpath="${dodwan_classpath}:${adapter_classpath}"
node_process_tag=casa.dodwan.run.dodwand

# ------------------------------------------------------------
# Functions used by LEPTON: start_node() and stop_node() are inherited
# from ${DODWAN_HOME}/bin/util/dodwan_functions.sh
# ------------------------------------------------------------

. ${DODWAN_HOME}/bin/util/dodwan_functions.sh


exec_on_node() {

    echo "Executing on ${node_id}: dodwan.sh $*"
    node_id=$node_id $DODWAN_HOME/bin/dodwan.sh $*
}

# ------------------------------------------------------------
# Variables used by DoDWAN nodes
# ------------------------------------------------------------

if [ "$lepton_host" == "" ] ; then
    echo "Warning: \$lepton_host is not defined. Assuming \$lepton_host=localhost."
    lepton_host=localhost
fi

# Define how to initialize DoDWAN nodes (used in start_node())
init_cmd="do tr add udp0 -t udp -ra ${lepton_host} -rp ${lepton_hub_port} -p 1 -use_tcp true"



exec_on_node() {

    echo "Executing on ${node_id}: dodwan.sh $@"
    node_id=$node_id $DODWAN_HOME/bin/dodwan.sh $@
}

# ------------------------------------------------------------
