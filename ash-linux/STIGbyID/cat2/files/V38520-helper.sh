#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38520
# Finding ID:	V-38520
# Version:	RHEL-06-000136
# Finding Level:	Medium
#
#     The operating system must back up audit records on an organization 
#     defined frequency onto a different system or media than the system 
#     being audited. A log server (loghost) receives syslog messages from 
#     one or more systems. This data can be used as an additional log 
#     source in the event a system is compromised and its local logs are 
#     suspect. ...
#
############################################################

CHKMOD=`rpm -qVf /etc/rsyslog.conf | grep '^..5'`


if [ "${CHKMOD}" == "" ]
then
   echo "WARN: rsyslog has not been configured"
   exit 0
else
   echo "Info:  /etc/rsyslog.conf modified - rsyslog may have been configured"
   exit 0
fi

