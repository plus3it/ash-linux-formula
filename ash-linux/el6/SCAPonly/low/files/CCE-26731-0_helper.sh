#!/bin/sh
#
# This Salt test/lockdown implements a SCAP item that has not yet been
# merged into the DISA-published STIGS
#
# Rule ID:
# - rpm_verify_permissions
#
# Security identifiers:
# - CCE-26731-0
#
# Rule Summary: Use RPM tools to verify correct file permissions
#
# Rule Text: Permissions on system binaries and configuration files that 
#            are too generous could allow an unauthorized user to gain 
#            privileges that they should not have. The permissions set 
#            by the vendor should be maintained. Any deviations from 
#            this baseline should be investigated. The RPM package 
#            management system can check file access permissions of 
#            installed software packages, including many that are 
#            important to system security. 
#
#################################################################
RESULT=0
FOUND=0

# Locate files with questionable modes
printf "Checking for files with bad permissions... "
QUERYFLT=" --nodigest --nosignature --nofiledigest --nouser --nogroup --nomtime"
BADPERMS=`rpm -qVa ${QUERYFLT} | awk '$1 ~ /.M/ && $2 != "c" {print $2}'`

echo "Done."

# Correct any questionable file-modes
if [ "${BADPERMS}" ]
then
   for CHECK in ${BADPERMS}
   do
      if [ -f ${CHECK} ]
      then
         FOUND=1
         RPMOWNS=`rpm -qf ${CHECK}`
         printf "Resetting perms on ${CHECK}... "
         rpm --setperms ${RPMOWNS}
         if [ $? -eq '0' ]
         then
            echo "FIXED!"
         else
            echo "FAILED!"
            RESULT=1
         fi
      fi
   done
fi

# Lets say if we've failed to find weird permissions
if [ ${FOUND} -eq 0 ]
then
   echo "******************************************"
   echo "* No files with questionable permissions *"
   echo "******************************************"
fi
   
exit ${RESULT}
