#!/bin/sh
# shellcheck disable=
#
# Script to implement firewalld 'safety' rules referenced by th
# firewalld_safeties state
#
#################################################################
PROGNAME="$(basename ${0})"
DEBUG="${DEBUG:-UNDEF}"
SELMODE="$(getenforce)"
ERRCTR=0
FWCMD="firewall-cmd"
FWCMDARGS="-q --direct --add-rule ipv4 filter INPUT_direct"

# Error handler function
function err_exit {
   local ERRSTR="${1}"
   local SCRIPTEXIT=${2:-1}

   ERRCTR=$((ERRCTR+=1))

   if [[ ${DEBUG} == true ]]
   then
      # Our output channels
      logger -i -t "${PROGNAME}" -p kern.crit -s -- "${ERRSTR}"
   fi

}

#############
## Main logic
#############

# Dial-back SEL as needed
if [[ ${SELMODE} == Enforcing ]]
then
   setenforce 0
fi

# Running-rules
${FWCMD} ${FWCMDARGS} 10 -m state --state RELATED,ESTABLISHED -m comment \
  --comment 'Allow related and established connections' -j ACCEPT || \
  err_exit 'Failed to add RELATED/ESTABLISHED exception to running config'
${FWCMD} ${FWCMDARGS} 20 -i lo -j ACCEPT || \
  err_exit 'Failed to add loopback exception to running config'
${FWCMD} ${FWCMDARGS} 30 -d 127.0.0.0/8 '!' -i lo -j DROP || \
  err_exit 'Failed to add loopback-spoofing to running config'
${FWCMD} ${FWCMDARGS} 50 -p tcp -m tcp --dport 22 -j ACCEPT || \
  err_exit 'Failed to protect SSH access in running config'

# Permanent-rules
${FWCMD} --permanent ${FWCMDARGS} 10 -m state --state RELATED,ESTABLISHED -m comment \
  --comment 'Allow related and established connections' -j ACCEPT || \
  err_exit 'Failed to add RELATED/ESTABLISHED exception to permanent config'
${FWCMD} --permanent ${FWCMDARGS} 20 -i lo -j ACCEPT || \
  err_exit 'Failed to add loopback exception to permanent config'
${FWCMD} --permanent ${FWCMDARGS} 30 -d 127.0.0.0/8 '!' -i lo -j DROP || \
  err_exit 'Failed to add loopback-spoofing to permanent config'
${FWCMD} --permanent ${FWCMDARGS} 50 -p tcp -m tcp --dport 22 -j ACCEPT || \
  err_exit 'Failed to protect SSH access in permanent config'

# Set SEL back to original mode (may be redundant)
setenforce "${SELMODE}"

# Provide stateful exit output
if [[ ${ERRCTR} -eq 0 ]]
then
   printf "\n"
   printf "changed=yes comment='Ensured safeties present in firewalld config.'\n"
   exit 0
else
   printf "\n"
   printf "changed=no comment='Failed to effect %s firewalld changes.'\n" "${ERRCTR}"
   exit 1
fi
