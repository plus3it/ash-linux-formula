#!/bin/sh
#
# Helper script to enumerate RPM-owned files whose MD5sum verifications fail
# - need to eventually replace with a native Salt/python module
#
############################################################################

VRFOPTS="--nofiles --nodigest --nosignature --nolinkto --nofiledigest --nosize --nouser --nogroup --nomtime --nordev --nocaps"
RPMFILES=`rpm -Va ${VRFOPTS} | awk '$1 ~ /^.M/ && $2 != "c"' | sed 's/^.*[ 	]\//\//'`

if [ "${RPMFILES}" == "" ]
then
   echo "Info: all RPM-owned files have expected mode-settings"
   exit 0
else
   for FILE in ${RPMFILES}
   do
     OWNERRPM=`rpm --qf "%{name}\n" -qf "${FILE}"`
     echo "${FILE} has unexpected mode-setting: manual-review required."
     echo "   Use rpm --setperms ${OWNERRPM} to revert to default."
   done
   exit 1
fi
