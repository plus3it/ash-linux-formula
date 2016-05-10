#!/bin/sh
#
# Script to generate STIG description scripts for Enterprise Linux 6
# STIG finding IDs
#
# Note: Create LISTFILE from the table at:
#    http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11
#
#########################################################################

LISTFILE=${1:-STIG-MAC-1_Classified}

BASEURL="http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding"

cat "${LISTFILE}" | \
while IFS= read -r FILE
do
   VULNID=`echo ${FILE} | cut -d ";" -f 1`
   VULNLV=`echo ${FILE} | cut -d ";" -f 2`
   VULNTXT=`echo ${FILE} | cut -d ";" -f 3`
   FILEID=`echo ${VULNID} | sed 's/V-/V/'`

#    touch ${VULNID}.sh
   (
   printf "#!/bin/sh\n#\n"
   printf "# STIG URL: ${BASEURL}/${VULNID}\n"
   printf "# Finding ID:\t${VULNID}\n"
   printf "# Version:\t\n"
   printf "# Finding Level:\t${VULNLV}\n"
   printf "#\n"
   printf "${VULNTXT}" | fold -sw 70 | sed 's/^/#     /'
   printf "\n#\n"
   printf "############################################################\n\n"
   ) > ${FILEID}.sh
done
