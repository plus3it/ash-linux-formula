#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38487
# Finding ID:	V-38487
# Version:	RHEL-06-000015
# Finding Level:	Low
#
#     The system package management tool must cryptographically verify the 
#     authenticity of all software packages during installation. Ensuring 
#     all packages' cryptographic signatures are valid prior to 
#     installation ensures the provenance of the software and protects 
#     against malicious tampering.
#
############################################################
FILELIST=`find /etc/yum.repos.d -type f | xargs grep -l gpgcheck=0`

if [ "${FILELIST}" = "" ]
then
   echo "All repos have gpgcheck enabled."
else
   for FILE in ${FILELIST}
   do
      echo "Found gpgcheck disabled in ${FILE}" > /dev/stderr
      sed -i '/gpgcheck=/s/0/1/' ${FILE} && echo "Reset gpgcheck to enabled in ${FILE}"
   done
fi   
