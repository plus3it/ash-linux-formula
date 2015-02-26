#!/bin/sh
#
# This Salt test/lockdown implements a SCAP item that has not yet been
# merged into the DISA-published STIGS
#
# Security identifiers:
# - CCE-26872-2
#
# Rule ID: no_files_unowned_by_group
#
# Rule Summary: Ensure All Files Are Owned by a Group
#
# Rule Text: If any files are not owned by a group, then the cause of 
#            their lack of group-ownership should be investigated. 
#            Following this, the files should be deleted or assigned to 
#            an appropriate group.
#
#            Unowned files do not directly imply a security problem, but 
#            they are generally a sign that something is amiss. They may 
#            be caused by an intruder, by incorrect software 
#            installation or draft software removal, or by failure to 
#            remove all files belonging to a deleted account. The files 
#            should be repaired so they will not cause problems when 
#            accounts are created in the future, and the cause should be 
#            discovered and addressed.
#
#
# NOTE: The salt file.find module doesn't have an option to handle
#       this internal to the framework. Resorting to this as a quick
#       work-around.
#
######################################################################

NOGRPOWN=`find / -fstype nfs -prune -o \( -nogroup \) -print 2> /dev/null`

if [ "${NOGRPOWN}" = "" ]
then
   RETCODE=0
   echo "No files with umapped group ownerships"
else
   RETCODE=1
   echo "*******************************" >&2
   for FILE in ${NOGRPOWN}
   do
      printf "Missing group ownership on:\n\t'${FILE}'\n" >&2
   done
   printf "\n*******************************\n" >&2
   echo "* MANUAL REMEDIATION REAUIRED *" >&2
   echo "*******************************" >&2
fi

exit ${RETCODE}
