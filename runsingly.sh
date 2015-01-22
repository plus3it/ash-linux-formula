#!/bin/sh
#
#
# Script to iterate though all of the VID SLS files and run them 
# singly. This script necessary until Jinja/state precendence 
# side-effects of unified Salt-run can be overcome
#
# NOTE: It is recommended to run this script with a log-capture 
# invocation method (i.e., "tack on '| tee /log/dir/log.file'")
#
#################################################################
VIDHOME="${1:-/srv/salt}"
DEBUGLVL="warning"
SALTCMD="/usr/bin/salt-call --no-color --local  -l ${DEBUGLVL} state.sls"
INSTALLED="false"

rpm -qf /usr/bin/salt-call && INSTALLED="true"

if [ "${INSTALLED}" = "false" ]
then
  echo "Saltstack RPMs not installed. Aborting!"
  exit 1
fi

# Locate all the VID SLS files and create a list
VIDLIST=`find -L ${VIDHOME} -type f -name "V*.sls" | sort | sed '{
s/^.*STIGbyID/STIGbyID/
s/\.sls$//
}'`

# Iterate individual VIDs from VID-list
for VID in ${VIDLIST}
do
   ${SALTCMD} ${VID}
done
