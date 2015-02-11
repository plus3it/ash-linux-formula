#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38678
# Finding ID:	V-38678
# Version:	RHEL-06-000311
# Finding Level:	Medium
#
#     The audit system must provide a warning when allocated audit record 
#     storage volume reaches a documented percentage of maximum audit 
#     record storage capacity. Notifying administrators of an impending 
#     disk space problem may allow them to take corrective action prior to 
#     any disruption.
#
############################################################

AUDITFS="/var/log/audit"
FREESPACE="0.25"

AUDFSCAP=`df -Pm ${AUDITFS} | awk '/%/{print $2}'`
AUDFREEVAL=`echo "${AUDFSCAP} * ${FREESPACE}" | bc | sed 's/\..*$//'`
