#!/bin/bash
#
# Helper script to return whether filsystem lives on a LUKS 
# device
#
#################################################################
DEVNODE=${1:-UNDEF}
MOUNTPT=${2:-UNDEF}

if [[ ${DEVNODE} = UNDEF || ${MOUNTPT} = UNDEF ]]
then
   printf "\n"
   printf "changed=no comment='insufficient aruments passed.'\n"
   exit 1
else
   VOLTYPE=$( lsblk -nl "${DEVNODE}" | awk '{ print $6 }' )
   if [[ ${VOLTYPE} == "crypt" ]]
   then
      printf "\n"
      printf "changed=no comment='%s hosted on encrypted " "${MOUNTPT}"
      printf "device [%s].'\n" "${DEVNODE}"
      exit 0
   else
      printf "\n"
      printf "changed=no comment='%s hosted on unencrypted " "${MOUNTPT}"
      printf "device [%s].'\n" "${DEVNODE}"
      exit 0
   fi
fi
