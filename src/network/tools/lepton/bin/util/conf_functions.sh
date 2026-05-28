#! /bin/bash

#  Utility functions to configure LEPTON. Used by all scripts

#  The names of the variables used in the bash scripts
bash_keys="lepton_host nodes_hosts oppnet_adapter jitter time_margin start_time nodes_steps nodes_deferred oppnet_adapter_classpath"

#  The lepton version
version=$(cat ${lepton_home}/VERSION)

#---------------------------------------------------------------------
#  Give the maven local repository
#---------------------------------------------------------------------
local_repository() {
    mvn help:evaluate -Dexpression=localRepository |grep basedir | sed 's/<\/\?basedir>//g' | sed 's/ //g'
}

#---------------------------------------------------------------------
#  Make a classpath with all the jar files in the libs/ directory
#---------------------------------------------------------------------
make_lepton_classpath() {

    libs_dir=${lepton_home}/libs

    if [ -f ${libs_dir}/dependencies ]; then
        wget -nc -nv -i ${libs_dir}/dependencies -P ${libs_dir}
    fi

    for i in ${libs_dir}/*.jar ; do
        classpath="${i}:${classpath}"
    done

    if [ "${oppnet_adapter_classpath}" != "" ]; then
        classpath="${oppnet_adapter_classpath}:${classpath}"
    fi

    echo "${classpath}"
}

#---------------------------------------------------------------------
#  Initialize bash variables from the configuration properties. Use
#  previousely saved properties if any
#---------------------------------------------------------------------
load_saved_config() {

    if [[ "${LEPTON_VAR}" != "" ]]; then
        log_dir=${LEPTON_VAR}
        echo "Using LEPTON_VAR: \"${LEPTON_VAR}\""
    else
        load_config "$@"
        echo "No LEPTON_VAR set. Using \"${log_dir}\""
    fi

    if [ -f ${log_dir}/.config ]; then
        echo "Loading the previous configuration from ${log_dir}/.config"
        load_config $(cat ${log_dir}/.config) "$@"
    elif [[ "${LEPTON_VAR}" != "" ]]; then
        load_config "$@"
    fi
}

#---------------------------------------------------------------------
#  Initialize bash variables from the configuration properties
#---------------------------------------------------------------------
load_config() {
    #  Load the default configuration file
    . ${lepton_home}/conf/lepton.conf

    #  Load the configuration properties in the script arguments
    for arg in "$@"; do
        key=${arg%=*}
        value=${arg#*=}
        if [ "$key" != "$value" ]; then
            case "$key" in
                "conf")       #  load the configuration file
                    . "$value"
                    ;;
                *)            #  initialize the variable
                    eval ${key}="${value}"
                    ;;
            esac
        fi
    done

    #  Create seed if it is not set
    if [ "${seed}" == "" ]; then
        seed=$(date +%s)
    fi
}

#---------------------------------------------------------------------
#  Display the bash properties having a non empty value
#---------------------------------------------------------------------
show_config() {
    for key in ${bash_keys}; do
        val=${!key}
        if [ "${val}" != "" ]; then
            str=""
            for (( i = ${#key}; i < 30; i++ )); do
                str="${str} "
            done
            echo "   ${key}${str}: ${val}"
        fi
    done
}

#---------------------------------------------------------------------
#  Utility functions to generate informations about nodes
#---------------------------------------------------------------------
#  Create a node id in the form "Nxxxxx" where xxxxx are digits
#  Arguments: node number, number of digits, [id prefix]
create_node_ID(){
    node_number=$1
    nb_digits=$2
    length=${#node_number}
    if [ $# -gt 2 ]; then
        node_id="$3"
    else
        node_id="N";
    fi
    #  Add zeros
    for (( i = ${length}; i < $((${nb_digits})); i++ )); do
        node_id="${node_id}0"
    done
    #  Add the node number
    node_id="${node_id}${node_number}"
    echo ${node_id}
}

#  Give the total number of nodes
#  Argument: ',' separated list of 'profile:nb'
get_nb_nodes() {
    sum=0
    for token in $(echo $1 | sed 's/,/ /g') ; do
        nb=${token#*:}
        sum=$((${nb} + ${sum}))
    done
    echo ${sum}
}

#  Give a random delay in ms from a given jitter in s.
#  Variables: jitter, num_node, randoms
get_random_delay() {
    if [ "${randoms}" != "" ]; then
        random=$(echo ${randoms} | cut -d" " -f$(($num_node+1)))
        echo $((${random}*${jitter}))
    else
        echo 0
    fi
}

#  Give random integers
#  Arguments: nb_values max_value base_seed
get_randoms() {
    seed=$3
    for (( i = 0; i < $1; i++ )); do
        seeds="${seeds} ${seed}"
        seed=$((${seed}+1000))
    done
    classpath=${lepton_home}/libs/casa-util-1.0.jar:${lepton_home}/libs/lepton-${version}.jar
    java -cp ${classpath} casa.util.randomizer $2 $seeds
}

#  Register a node as being started or stopped
#  Arguments: node_id true|false
set_node_started() {
    if [ "$2" == "true" ]; then
        if [ ! -d ${log_dir}/.nodes ]; then mkdir ${log_dir}/.nodes ; fi
        touch ${log_dir}/.nodes/$1
    elif [ -d ${log_dir}/.nodes ]; then
        rm -f ${log_dir}/.nodes/$1
    fi
}
