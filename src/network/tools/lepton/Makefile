#  Makefile to prepare and compile the LEPTON project
#  targets:
#      all          build a version of LEPTON
#      clean        remove generated files and directories

#  Default configuration files
CONFIG = lepton.conf
VERSION ?= $(shell mvn help:evaluate -Dexpression=project.version | grep -v INFO)

#====================================================================
#  Main targets
#====================================================================

#  Build a version of LEPTON
all: build copy_config

#  Remove the libs/ and target/ directories
clean:
	rm -rf libs/ target/

#====================================================================
#  Intermediate targets
#====================================================================

#  Build the maven project
build: clean
	@echo $(VERSION) > VERSION
	@mvn -DskipTests install

#  Populate the conf/ directory with copies of the default configuration files
copy_config:
	mkdir -p src/main/resources/conf
	@for i in $(CONFIG); do \
		cp conf/$$i src/main/resources/conf/; \
	done
