#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38453
# Finding ID:	V-38453
# Version:	RHEL-06-000517
# Finding Level:	Low
#
#     Group-ownership of system binaries and configuration files that is 
#     incorrect could allow an unauthorized user to gain privileges that 
#     they should not have. The group-ownership set by the vendor should be 
#     maintained. Any deviations from this baseline should be investigated. 
#
#  CCI: CCI-000366
#  NIST SP 800-53 :: CM-6 b
#  NIST SP 800-53A :: CM-6.1 (iv)
#  NIST SP 800-53 Revision 4 :: CM-6 b
#
############################################################

VRFOPTS="--nofiles --nodigest --nosignature --nolinkto --nofiledigest --nosize --nogroup --nomtime --nomode --nocaps"
RPMFILES=`rpm -Va ${VRFOPTS}| awk '$1 ~ /'^.....U'/ && $2 != "c"' | sed 's/^.*[ 	]\//\//'`

if [ "${RPMFILES}" == "" ]
then
   echo "Info: all RPM-owned files have expected user-ownerships"
   exit 0
else
   for FILE in ${RPMFILES}
   do
     OWNERRPM=`rpm --qf "%{name}\n" -qf "${FILE}"`
     echo "${FILE} has unexpected user-ownership:"
     echo "  fix with rpm --setugids ${OWNERRPM}."
     if [ "${FIXRPMSRAW}" = "" ]
     then
        FIXRPMSRAW="${OWNERRPM}"
     else
        FIXRPMSRAW="${FIXRPMSRAW} ${OWNERRPM}"
     fi
   done
   FIXRPMS=`echo ${FIXRPMSRAW} | sed 's/ /\n/g' | sort -u`
   for RPM in ${FIXRPMS}
   do
      echo "Fixing ${RPM} file user ownerships..."
      rpm --setugids ${RPM}
   done
fi
