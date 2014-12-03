#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38699
# Finding ID:	V-38699
# Version:	RHEL-06-000337
# Finding Level:	Low
#
#     Allowing a user account to own a world-writable directory is 
#     undesirable because it allows the owner of that directory to remove 
#     or replace any files that may be placed in the directory by other 
#     users. 
#
#  CCI: CCI-000366
#  NIST SP 800-53 :: CM-6 b
#  NIST SP 800-53A :: CM-6.1 (iv)
#  NIST SP 800-53 Revision 4 :: CM-6 b
#
############################################################

FSMOUNTS=`egrep "(ext2|ext3|ext4|xfs)" /etc/fstab | awk '{print $2}'`
for FS in ${FSMOUNTS}
do
   OFFENDERS=`find "${FS}" -xdev -type d -perm -0002 -uid +499 -print`
   if [ "${OFFENDERS}" = "" ]
   then
      echo "All world-writable directories in ${FS} are owned by system accounts"
      SETEXIT=0
   else
      for OFFENDER in ${OFFENDERS}
      do
         echo "Found user-owned world-writable directory [${OFFENDER}]"
         SETEXIT=1
      done
   fi
done

exit ${SETEXIT}
