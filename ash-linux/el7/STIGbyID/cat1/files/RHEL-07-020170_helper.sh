#!/bin/sh
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
   VOLTYPE=$(lsblk -nl ${DEVNODE} | awk '{print $6}')
   if [[ ${VOLTYPE} = crypt ]]
   then
      printf "\n"
      printf "changed=no comment='${MOUNTPT} hosted on encrypted "
      printf "device [${DEVNODE}].'\n"
      exit 0
   else
      printf "\n"
      printf "changed=no comment='${MOUNTPT} hosted on unencrypted "
      printf "device [${DEVNODE}].'\n"
      exit 0
   fi
fi
