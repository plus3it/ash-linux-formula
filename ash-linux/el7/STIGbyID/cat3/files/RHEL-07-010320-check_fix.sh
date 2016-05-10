#!/bin/sh
#
# STIG URL:
# Finding ID:	RHEL-07-010320
# Version:	RHEL-07-010320_rule
# SRG ID:	SRG-OS-000123-GPOS-00064
# Finding Level:	low
#
# Rule Summary:
#     The operating system must be configured such that emergency 
#     administrator accounts are never automatically removed or 
#     disabled.
#
# CCI-001682
#    NIST SP 800-53 :: AC-2 (2)
#    NIST SP 800-53A :: AC-2 (2).1 (ii)
#    NIST SP 800-53 Revision 4 :: AC-2 (2)
#
#################################################################
ADMUSER=${1:-root}

# Check who's calling
function ValidRequestor () {
   if [[ "$(whoami)" = root ]]
   then
      echo "0"
   else
      echo "1"
   fi
}


# Check current expiry-state
function ChkCurState() {
   local EXPIRY="$(chage -l "${ADMUSER}" | \
                   awk '/Password expires/{print $4}')"
   if [[ "${EXPIRY}" = "never" ]]
   then
      echo 0
   else
      echo 1
   fi
}


# Try to disable expiry
function SetNoExpire() {
   chage -I -1 -M 99999 "${ADMUSER}"
   echo "$?"
}


# Ensure run as root
if [[ $(ValidRequestor)$? -ne 0 ]]
then
   printf "\n"
   printf "changed=no comment='Must be root user to change this value.'\n"
   exit 1
fi

# Check current expiry-state
if [[ $(ChkCurState)$? -eq 0 ]]
then
   printf "\n"
   printf "changed=no comment='Password for ${ADMUSER} is already set to "
   printf "not expire.'\n"
   exit 0
# Expiry-disablement succeeded
elif [[ $(SetNoExpire)$? -eq 0 ]]
then
   printf "\n"
   printf "changed=yes comment='Password for ${ADMUSER} now set to "
   printf "not expire.'\n"
   exit 0
# Expiry-disablement failed
elif [[ $(SetNoExpire)$? -eq 1 ]]
then
   printf "\n"
   printf "changed=no comment='Failed to set password for ${ADMUSER} to "
   printf "not expire.'\n"
   exit 1
fi
