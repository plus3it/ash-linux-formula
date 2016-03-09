#!/bin/sh
# 
# Convert table contents:
# 
#    Vuln ID|Severity|Rule ID|STIG ID|Rule Title|Discussion|CCI Data
# 
# to files/content. File content should resemble:
# 
#     STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38702
#     Finding ID:   V-38702
#     Version:      RHEL-06-000339
#     Finding Level:        Low
#    
#         The FTP daemon must be configured for logging or verbose mode. To
#         trace malicious activity facilitated by the FTP service, it must be
#         configured to ensure that all commands sent to the ftp server are
#         logged using the verbose vsftpd log format. The default vsftpd log
#         file is /var/log/vsftpd.log
#
#     CCI: CCI-000130
#     NIST SP 800-53 :: AU-3
#     NIST SP 800-53A :: AU-3.1
#     NIST SP 800-53 Revision 4 :: AU-3
#
#################################################################

#  STIG URL:
#  Finding ID:  RHEL-07-010020
#  Version:     SRG-OS-000004-GPOS-00004
#  Finding Level:       medium
#
#  Rule Summary:
#     RHEL-07-010020

STIGFILE=${1:-EL7-DraftSTIG-2.txt}

for LINE in $(seq 1 $(wc -l "${STIGFILE}" | awk '{print $1}'))
do
   if [[ ${LINE} -gt 1 ]]
   then
      TXTLN=($(sed -n ${LINE}p "${STIGFILE}"))
      VULNID=$(echo ${TXTLN[@]} | awk -F "|" '{print $1}')
      CATLVL=$(echo ${TXTLN[@]} | awk -F "|" '{print $2}')
#     SRGNUM=$(echo ${TXTLN[@]} | awk -F "|" '{print $3}')
      RULEID=$(echo ${TXTLN[@]} | awk -F "|" '{print $3}')
      STIGID=$(echo ${TXTLN[@]} | awk -F "|" '{print $4}')
      RULETT=$(echo ${TXTLN[@]} | awk -F "|" '{print $5}')
      DISCUS=$(echo ${TXTLN[@]} | awk -F "|" '{print $6}')
#     SRGNUM=$(echo ${TXTLN[@]} | awk -F "|" '{print $6}' | sed 's/^.*Satisfies: //')
      CCIDAT=$(echo ${TXTLN[@]} | awk -F "|" '{print $7}')
      case ${CATLVL} in
         high)
            DIR=cat1
            ;;
         medium)
            DIR=cat2
            ;;
         low)
            DIR=cat3
            ;;
      esac

      echo "Creating ${DIR}/${VULNID}.sls"

      (
       cat << EOF
#!/bin/sh
#
# STIG URL:
# Finding ID:	${VULNID[@]}
# Version:	${RULEID[@]}
# SRG ID:	${SRGNUM[@]}
# Finding Level:	${CATLVL[@]}
#
# Rule Summary:
EOF
       echo ${RULETT[@]} | fold -sw 65 | sed 's/^/#     /'
       echo "#"
       echo ${CCIDAT} | sed 's/ NIST/\n   NIST/g' | sed -e 's/^/# /'
       echo "#"
       echo "#################################################################"
      ) > ${DIR}/${VULNID}.sls
   fi
done
