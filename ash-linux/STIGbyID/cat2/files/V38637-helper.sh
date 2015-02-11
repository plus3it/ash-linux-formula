#!/bin/sh
#
# Helper-script for STIG V-38637
#
#################################################################

CHKTAMPER=`rpm -V audit | awk '$1 ~ /..5/ && $2 != "c"'`

if [ "${CHKTAMPER}" = "" ]
then
   echo "RPM verification passed"
   exit 0
else
   echo "RPM verification FAILED"
   exit 1
fi
