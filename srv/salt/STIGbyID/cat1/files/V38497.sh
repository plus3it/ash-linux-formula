#!/bin/bash
# 
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38497
# Finding ID: V-38497
# Version: RHEL-06-000030
#
#   (GEN000560: CAT I) (Previously G018) The SA will ensure each account 
#      in the /etc/passwd file has a password assigned or is disabled in
#      the password, shadow, or equivalent, file by disabling the password
#      and/or by assigning a false shell in the password file.
#
##########################################################################

echo '==================================================='
echo ' Patching GEN000560: Disable accounts with no'
echo '                     password'
echo '==================================================='

RESET=0

/usr/sbin/pwconv && \
   echo "INFO: Flushed all /etc/passwd password entries to /etc/shadow"

for USERINFO in `cat /etc/shadow`; do
   if [ -z "`echo $USERINFO | cut -d: -f2`" ]; then
      CHGUSER=`echo $USERINFO | cut -d: -f1` 
      /usr/sbin/usermod -L -s /dev/null ${CHGUSER} && \
         echo "User \"${CHGUSER}\" had empty password. Account now locked."
      RESET=1
   fi
done;

if [ ${RESET} -eq 0 ]
then
   echo "No users with empty passwords found"
fi
