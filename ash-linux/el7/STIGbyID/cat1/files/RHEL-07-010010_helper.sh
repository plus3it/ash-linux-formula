#!/bin/bash
#
# Finding ID:	RHEL-07-010010
# Version:	RHEL-07-010010_rule
# SRG ID:	SRG-OS-000257-GPOS-00098
# Finding Level:	high
#
# Rule Summary:
#	The file permissions, ownership, and group membership of
#	system files and commands must match the vendor values.
#
# CCI-001494 CCI-001496
#    NIST SP 800-53 :: AU-9
#    NIST SP 800-53A :: AU-9.1
#    NIST SP 800-53 Revision 4 :: AU-9
#    NIST SP 800-53 :: AU-9 (3)
#    NIST SP 800-53A :: AU-9 (3).1
#    NIST SP 800-53 Revision 4 :: AU-9 (3)
#
#################################################################
RESULT=0
FOUND=0

# Locate files with questionable modes
printf "Checking for files with bad permissions... \n"
QUERYFLT=" --nodigest --nosignature --nofiledigest --nouser --nogroup --nomtime"
BADPERMS=$(rpm -qVa ${QUERYFLT} | \
           awk '$1 ~ /.M/ && $2 != "c" {print $2}')

# Correct any questionable file-modes
if [ "${BADPERMS}" ]
then
   for CHECK in ${BADPERMS}
   do
      if [ -f ${CHECK} ]
      then
         FOUND=1
         RPMOWNS=$(rpm -qf "${CHECK}")
         printf "Resetting perms on ${CHECK}... "
         rpm --setperms ${RPMOWNS}
         if [ $? -eq '0' ]
         then
            echo "FIXED!"
            RESULT=$((${RESULT} + 0))
         else
            echo "FAILED!"
            RESULT=$((${RESULT} + 1))
         fi
      fi
   done
   if [[ ${FOUND} -eq 1 ]]
   then
      if [[ ${RESULT} -eq 0 ]]
      then
         printf "\n"
         printf "changed=yes comment='One or more files with bad modes "
         printf "corrected.'\n"
         exit 0
      else
         printf "\n"
         printf "changed=no comment='Failed to correct one or more files "
         printf "with bad modes.'\n"
         exit 1
      fi
   fi
fi

# Lets say if we've failed to find weird permissions
if [ ${FOUND} -eq 0 ]
then
   echo "No mis-permissioned files found"
   printf "\n"
   printf "changed=no comment='No files with bad modes.'\n"
   exit 0
fi
