#!/bin/bash
#
# Finding ID:	RHEL-07-010020
# Version:	RHEL-07-010020_rule
# SRG ID:	SRG-OS-000480-GPOS-00227
# Finding Level:	high
# 
# Rule Summary:
#	The cryptographic hash of system files and commands must
#	match vendor values.
#
# CCI-000663 
#    NIST SP 800-53 :: SA-7 
#    NIST SP 800-53A :: SA-7.1 (ii) 
#
#################################################################
VRFOPTS="--noscripts --nolinkto --nosize --nouser --nogroup --nomtime --nomode --nordev --nocaps"
RPMFILES=$(rpm -Va ${VRFOPTS} | awk '$1 ~ /^..5/ && $2 != "c"' | \
           sed 's/^.*[ 	]\//\//')
RPMARRAY=()

if [ "${RPMFILES}" == "" ]
then
   echo "Info: all RPM-owned files passed MD5 verification"
   printf "\n"
   printf "changed=no comment='No files with bad MD5s.'\n"
   exit 0
else
   for FILE in ${RPMFILES}
   do
     OWNERRPM=`rpm --qf "%{name}\n" -qf "${FILE}"`
     echo "${FILE} (${OWNERRPM}) failed MD5 checksum!"
     RPMARRAY+=(${OWNERRPM})
   done
   yum -q reinstall -y ${RPMARRAY[@]}
   if [[ $? -eq 0 ]]
   then
      printf "\n"
      printf "changed=yes comment='Reinstalled RPMs to correct MD5s for "
      printf "one or more files.'\n"
      exit 0
   else
      printf "\n"
      printf "changed=no comment='Failed to correct one or more files "
      printf "with bad MD5s.'\n"
      exit 1
   fi
fi
