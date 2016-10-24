#!/bin/sh
# Finding ID:	RHEL-07-020860
# Version:	RHEL-07-020860_rule
# SRG ID:	SRG-OS-000480-GPOS-00227
# Finding Level:	medium
# 
# Rule Summary:
#	All local initialization files must have mode 0740 or less permissive.
#
# CCI-000366 
#    NIST SP 800-53 :: CM-6 b 
#    NIST SP 800-53A :: CM-6.1 (iv) 
#    NIST SP 800-53 Revision 4 :: CM-6 b 
#
#################################################################
# Receive value of dir-to-check from state file
CHECKPATH=${1:-UNDEF}
CHECKDIR=$(dirname "$(echo ${CHECKPATH})")
INITFILE=$(basename "$(echo ${CHECKPATH})")
PATHMODE=$(stat -c %a "${CHECKPATH}")

if [[ ${PATHMODE:1:1} -ge 5 ]] || [[ ${PATHMODE:2:1} -gt 0 ]]
then
   chmod g-wx,o-rwx "${CHECKPATH}"
   printf "\n"
   printf "changed=yes comment='Stripped permissions from ${CHECKPATH}'\n"
   exit 0
else
   printf "\n"
   printf "changed=no comment='Found no offending permissions on ${CHECKPATH}'\n"
   exit 0
fi

