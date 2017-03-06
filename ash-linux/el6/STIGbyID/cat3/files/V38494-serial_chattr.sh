#!/bin/sh
#
# Helper-module for V38494 to handle setting the immutable flag
# on the critical configuration file
#
#################################################################

if [[ $# -lt 1 ]]
then
   printf "\n"
   printf "changed=no comment='Insufficient number of arguments "
   printf "passed.'\n"
   exit 1
else
   MODFILE=${1}
fi

if [[ -L ${MODFILE} ]]
then
   MODFILE=$(readlink -f ${MODFILE})
fi

if [[ ! -f ${MODFILE} ]]
then
   printf "\n"
   printf "changed=no comment='Target [${MODFILE}] does not "
   printf "exist.'\n"
   exit 1
fi

CURATTRIB=$(lsattr ${MODFILE} | cut -c 5)

if [[ ${CURATTRIB} = "i" ]]
then
   printf "\n"
   printf "changed=no comment='${MODFILE} already set immutable. "
   printf "Nothing to do.'\n"
   exit 0
else
   chattr +i ${MODFILE}
   if [[ $? -eq 0 ]]
   then
      printf "\n"
      printf "changed=yes comment='Set immutable flag on "
      printf "${MODFILE}.'\n"
      exit 0
   else
      printf "\n"
      printf "changed=no comment='Failed to set immutable flag "
      printf "on ${MODFILE}.'\n"
      exit 1
   fi
fi
