#!/bin/sh
#
# HELPER-script
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38663
# Finding ID:	V-38663
# Version:	RHEL-06-000278
# Finding Level:	Medium
#
#     The system package management tool must verify ownership on all files 
#     and directories associated with the audit package. Ownership of audit 
#     binaries and configuration files that is incorrect could allow an 
#     unauthorized user to gain privileges that they should not have. The 
#     ownership set by the vendor should be ...
#
############################################################

CHECKRPM=`rpm -V audit | grep '^.M'`

if [ "${CHECKRPM}" == "" ]
then
   echo "Info: 'audit' RPM passes permissions verification"
   exit 0
else
   echo "WARN: 'audit' RPM FAILS permissions verification - manual intervention required"
   exit 0
fi
