#!/bin/sh
#
# Make setting up the Saltstack SLS file-paths dead-easy
#
######################################################################
SETUPFQP=`readlink -f ${0}`
SETUPROOT=`dirname ${SETUPFQP}`
SALTHOME="srv/salt"
SLSROOT="${SETUPROOT}/${SALTHOME}"
LINKLIST="top.sls STIGbyID"


if [ ! -d /${SALTHOME} ]
then
   # Create home directory for SLS files
   printf "Creating /${SALTHOME}"
   install -d -m 0755 -o root -g root /${SALTHOME} && echo "...done"
fi

# Create our symlinks in /${SALTHOME}
for TARG in ${LINKLIST}
do
   if [ -e ${SLSROOT}/${TARG} ]
   then
      if [ -L /${SALTHOME}/${TARG} ]
      then
         echo "/${SALTHOME}/${TARG} already exists as link"
      else
         printf "Creating symlink at /${SALTHOME}/${TARG}... "
         ln -s ${SLSROOT}/${TARG} /${SALTHOME}/${TARG} && echo "Success."
      fi
   fi
done

# Make sure /usr/local/bin exists
if [ ! -d /usr/local/bin ]
then
   install -d -m 0755 -o root -g root /usr/local/bin
fi

# Copy our output filter to /usr/local/bin
install -m 0755 -o root -g root ${SETUPROOT}/outFilter.sed /usr/local/bin/SaltOutFilter.sh

