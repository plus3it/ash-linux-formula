#!/bin/sh

LISTFILE=${1:-STIG-MAC-1_Classified}

BASEURL="http://www.stigviewer.com/stig/unix_srg/2013-03-26/finding"

cat "${LISTFILE}" | \
while IFS= read -r FILE
do
   VULNID=`echo ${FILE} | cut -d ";" -f 1`
   VULNLV=`echo ${FILE} | cut -d ";" -f 2`
   VULNSUM=`echo ${FILE} | cut -d ";" -f 3`
   VULNTXT=`echo ${FILE} | cut -d ";" -f 4`
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

