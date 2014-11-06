#!/bin/sh
#
# Helper script to enumerate RPM-owned files whose MD5sum verifications fail
# - need to eventually replace with a native Salt/python module
#
############################################################################
RPMFILES=` rpm -Va | awk '$1 ~ /^..5/ && $2 != "c"' | sed 's/^.*[ 	]\//\//'`

if [ "${RPMFILES}" == "" ]
then
   echo "Info: all RPM-owned files passed MD5 verification"
   exit 0
else
   for FILE in ${RPMFILES}
   do
     OWNERRPM=`rpm --qf "%{name}\n" -qf "${FILE}"`
     echo "${FILE} (${OWNERRPM}) failed MD5 checksum: manual remediation required"
   done
   exit 1
fi
