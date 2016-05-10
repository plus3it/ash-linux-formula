#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38480
# Finding ID:	V-38480
# Version:	RHEL-06-000054
# Finding Level:	Low
#
#     Users must be warned 7 days in advance of password expiration. 
#     Setting the password warning age enables users to make the change at 
#     a practical time.
#
############################################################
LOGINDEFS="/etc/login.defs"
MINDAY=7

WARNSET=`awk '/PASS_WARN_AGE/ && $1 !="#"' ${LOGINDEFS} | sed 's/AGE[   ]*/AGE;/'`

if [ "${WARNSET}" = "" ]
then
   echo "Password warning parm not set. Setting..."
   printf "PASS_WARN_AGE\t7\n" >> ${LOGINDEFS}
else
   CURDAYS=`echo ${WARNSET} | cut -d ";" -f 2`
   if [ ${CURDAYS} -ge ${MINDAY} ]
   then
      echo "Current PASS_WARN_AGE value [${CURDAYS}] meets DoD Minimums"
   else
      echo "Resetting PASS_WARN_AGE value to DoD Minimum [${MINDAY}]"
      sed -i 's/^PASS_WARN_AGE.*$/PASS_WARN_AGE	'${MINDAY}'/' ${LOGINDEFS}
   fi
fi
