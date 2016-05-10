#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38567
# Finding ID:	V-38567
# Version:	RHEL-06-000198
# Finding Level:	Low
#
#     The audit system must be configured to audit all use of setuid 
#     programs. Privileged programs are subject to escalation-of-privilege 
#     attacks, which attempt to subvert their normal role of providing some 
#     necessary but limited capability. As such, motivation exists to 
#     monitor these programs for unusual activity.
#
############################################################
RULEFILE='/etc/audit/audit.rules'

GETBLKDEVS=`mount | awk '/ ext[234]/{print $3}'`

FILELIST=`for FILESYS in ${GETBLKDEVS}
do
   find "${FILESYS}" -xdev -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null
done`

if [ "${FILELIST}" = "" ]
then
   echo "Nothing to add to ${RULEFILE}"
else
   echo "# Monitor for suid/sgid files (per STIG-ID V-38567)" >> ${RULEFILE}
   for TARGET in ${FILELIST}
   do
      grep -qw "${TARGET}" ${RULEFILE}
      if [ $? -eq 0 ]
      then
         echo "${TARGET} already monitored in ${RULEFILE}"
      else
         echo "Adding ${TARGET} for monitoring in ${RULEFILE}"
         echo "-a always,exit -F path=${TARGET} -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged" >> ${RULEFILE}
      fi
   done
fi
