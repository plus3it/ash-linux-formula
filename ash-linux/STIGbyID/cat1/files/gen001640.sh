#!/bin/sh
#
# Group ID (Vulid): V-910
# Group Title: Run Control Scripts World Writable Scripts
# Rule ID: SV-910r6_rule
# Severity: CAT I
# Rule Version (STIG-ID): GEN001640
# Rule Title: Run control scripts must not execute world-writable programs 
#   or scripts.
#
# Vulnerability Discussion: World-writable files could be modified 
# accidentally or maliciously to compromise system integrity.
#
# Responsibility: System Administrator
# IAControls: ECCD-1, ECCD-2
#
# Check Content: 
#   Check the permissions on the files or scripts executed from system 
#   startup scripts to see if they are world-writable.
#
#######################DISA INFORMATION###############################

echo '==================================================='
echo ' Patching GEN001640: Remove World-Write Permission'
echo ' From Files Referenced By Init-Scripts'
echo '==================================================='

# Find all files that are world-writable...
find / \( -path /proc -o -path /sys \) -prune -o \
   -perm -o=w -type f -print0 | \

# ...and check system startup scripts to determine if any are referenced.
while IFS= read -r -d '' FILE;
do
   REFLIST=`egrep -l -r "${FILE}" /etc/rc.d`
   if [ $? -eq 1 ]
   then
      printf "NOTE: \"${FILE}\" world-writable but not\n"
      printf "\treferenced by any init-scripts. [WONT CHANGE]\n"
   else
      printf "FINDING: \"${FILE}\" is referenced in:\n${REFLIST}\n"
      chmod o-w "${FILE}" && echo "\"${FILE}\" has had world-write stripped"
   fi
done

