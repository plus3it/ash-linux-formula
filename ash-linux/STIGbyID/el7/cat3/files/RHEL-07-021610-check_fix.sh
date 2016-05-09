#!/bin/sh
#
# STIG URL:
# Finding ID:	RHEL-07-021610
# Version:	RHEL-07-021610_rule
# SRG ID:	
# Finding Level:	low
#
# Rule Summary:
#     The file integrity tool must be configured to verify extended 
#     attributes.
#
# CCI-000366
#    NIST SP 800-53 :: CM-6 b
#    NIST SP 800-53A :: CM-6.1 (iv)
#    NIST SP 800-53 Revision 4 :: CM-6 b
#
#################################################################
CHKPKG=${1:-aide}
CHKOBJ=${2:-/etc/aide.conf}

# Check who's calling
function ValidRequestor () {
   if [[ "$(whoami)" = root ]]
   then
      echo "0"
   else
      echo "1"
   fi
}


# Check if target file is unaltered
function CheckFIle() {
   if [[ $(rpm -qV ${CHKPKG} | awk '$2 == "c" {print $3}' | \
           grep -q ${CHKOBJ})$? -eq 0 ]]
   then
      echo 1
   else
      echo 0
   fi
}


# Ensure run as root
if [[ $(ValidRequestor)$? -ne 0 ]]
then
   printf "\n"
   printf "changed=no comment='Must be root user to change this value.'\n"
   exit 1
fi

if [[ $(CheckFIle)$? -eq 0 ]]
then
   printf "\n"
   printf "changed=no comment='Default configuration for ${CHKOBJ} is STIG-"
   printf "compliant by default.'\n"
   exit 0
else
   printf "\n"
   printf "changed=no comment='<<<WARNING>>> Config for ${CHKOBJ} altered "
   printf "from vendor-defaults. Please manually-check if new configuration "
   printf "is STIG-compliant. <<<WARNING>>>'\n"
   exit 0
fi
