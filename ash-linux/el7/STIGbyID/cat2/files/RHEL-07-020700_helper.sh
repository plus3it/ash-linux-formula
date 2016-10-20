#!/bin/sh
# Finding ID:	RHEL-07-020700
# Version:	RHEL-07-020700_rule
# SRG ID:	SRG-OS-000480-GPOS-00227
# Finding Level:	medium
# 
# Rule Summary:
#	All files and directories contained in local interactive user
#	home directories must have mode 0750 or less permissive.
#
# CCI-000366 
#    NIST SP 800-53 :: CM-6 b 
#    NIST SP 800-53A :: CM-6.1 (iv) 
#    NIST SP 800-53 Revision 4 :: CM-6 b 
#
#################################################################
# Receive value of dir-to-check from state file
CHECKDIR=${1:-UNDEF}
LOOP=0

FIXED=($(find -L ${CHECKDIR} -perm /027 -type f -exec printf \
  "{}\n" \; -exec chmod g-w,o-rwx {} \;))

if [[ ${LOOP} -lt ${#FIXED[@]} ]]
then
   echo "Stripped permissions from"
   for FILE in ${FIXED[@]}
   do
     echo ${FILE} | sed 's#^#   #'
   done

   printf "\n"
   printf "changed=yes comment='Stripped permissions from objects in "
   printf "${CHECKDIR}'\n"
   exit 0
else
   printf "\n"
   printf "changed=no comment='Found no offending permissions in "
   printf "${CHECKDIR}'\n"
   exit 0
fi

