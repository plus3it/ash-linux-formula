#!/bin/sh
#
# Helper script to enumerate RPM-owned files whose MD5sum verifications fail
# - need to eventually replace with a native Salt/python module
#
############################################################################
RPMFILES=`rpm -Va | grep '/^..5/' | sed 's/^.*[ 	]\//\//'`


if [ "${RPMFILES}" == "" ]
then
   echo "Info: all RPM-owned files passed MD5 verification"
   exit 0
else
   for FILE in ${RPMFILES}
   do
     OWNERRPM=`rpm --qf "%{name}\n" -qf "${FILE}"`
     echo "${OWNERRPM}'s file ${FILE} failed MD5 checksum: please verify its contents"
   done
   exit 1
fi
