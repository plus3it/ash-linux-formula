#!/bin/sh
#
# HELPER-script
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38664
# Finding ID:	V-38664
# Version:	RHEL-06-000279
# Finding Level:	Medium
#
#     The system package management tool must verify ownership on all files 
#     and directories associated with the audit package. Ownership of audit 
#     binaries and configuration files that is incorrect could allow an 
#     unauthorized user to gain privileges that they should not have. The 
#     ownership set by the vendor should be ...
#
############################################################

CHECKRPM=`rpm -V audit | grep '^.....U'`

if [ "${CHECKRPM}" == "" ]
then
   echo "Info: 'audit' RPM passes ownership verification"
   exit 0
else
   echo "WARN: 'audit' RPM FAILS ownership verification - manual intervention required"
   exit 1
fi
