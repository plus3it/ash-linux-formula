#!/bin/sh
#
# STIG URL:
# Finding ID:	RHEL-07-020430
# Version:	RHEL-07-020430_rule
# SRG ID:	
# Finding Level:	low
#
# Rule Summary:
#     Manual page files must have mode 0644 or less permissive.
#
# CCI-000366
#    NIST SP 800-53 :: CM-6 b
#    NIST SP 800-53A :: CM-6.1 (iv)
#    NIST SP 800-53 Revision 4 :: CM-6 b
#
#################################################################

CHECKDIR=${1:-UNDEF}

# Fix perms
function FixPerms() {
   local LOOP=0
   while [[ ${LOOP} -lt ${#FILELIST[@]} ]]
   do
      chmod g-w,o-w "${FILELIST[${LOOP}]}" > /dev/null 2>&1
      if [[ $? -eq 0 ]]
      then
         CHANGED[${#CHANGED[@]}]="${FILELIST[${LOOP}]}"
      else
         UNCHANGED[${#UNCHANGED[@]}]="${FILELIST[${LOOP}]}"
      fi
      LOOP=$((${LOOP} + 1))
   done
}


IFS=$'\n' 
FILELIST=($(find -L "${CHECKDIR}" -type f -perm /g+w,o+w))
unset IFS

if [[ ${#FILELIST[@]} -eq 0 ]]
then
   printf "\n"
   printf "changed=no comment='No group- or world-writable files found "
   printf "in ${CHECKDIR}.'\n"
   exit 0
else
   FixPerms 
   if [[ ${#UNCHANGED[@]} -eq 0 ]]
   then
      printf "\n"
      printf "changed=yes comment='Perms fixed on: "
      echo "${CHANGED[@]}'"
      exit 0
   else
      printf "\n"
      printf "changed=no comment='Failed to change the files: "
      echo "${UNCHANGED[@]}'"
      exit 1
   fi
fi
