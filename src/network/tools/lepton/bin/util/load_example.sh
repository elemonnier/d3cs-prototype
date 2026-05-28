#!/bin/bash

# A script that loads a zip file from a given URL and unzip it to the
# example directory. Help should display the list of available zip
# files (found in the examples directory or at the remote URL?)

script_dir=$(dirname $0)
lepton_home=$(realpath ${script_dir}/../..)
url="http://share-irisa.univ-ubs.fr/casa/pub/software/lepton/examples"

usage() {
    echo "Usage: $0 <example_scenario>"
    echo "With <example_scenario>:"
    wget -qO- ${url}/list
    exit -1
}

if (( $# < 1 )) || [ "$1" == "-h" ]; then
    usage
fi

example=$1
for i in $(wget -qO- ${url}/list); do
    if [ "$1" == "$i" ]; then
	found=true
    fi
done

if [ "$found" != "true" ]; then
    echo "Example \"${example}\" does not exist"
    exit -1
fi

if [ ! -d ${lepton_home}/examples ]; then
    mkdir ${lepton_home}/examples
fi    

wget ${url}/${example}.zip && {
    rm -rf ${lepton_home}/examples/${example}
    unzip ${example}.zip -d ${lepton_home}/examples
    rm -f ${example}.zip
    echo "Example \"${example}\" loaded in ${lepton_home}/examples/${example}"
    echo "Run: lepton.sh start conf=${lepton_home}/examples/${example}/lepton.conf"
}
