# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38623
# Finding ID:	V-38623
# Version:	RHEL-06-000135
# Finding Level:	Medium
#
#     All rsyslog-generated log files must have mode 0600 or less 
#     permissive. Log files can contain valuable information regarding 
#     system configuration. If the system log files are not protected, 
#     unauthorized users could change the logged data, eliminating their 
#     forensic value.
#
############################################################

script_V38623-describe:
  cmd.script:
  - source: salt://STIGbyID/cat2/files/V38623.sh

cmd_V38623-NotImplemented:
  cmd.run:
  - name: 'echo "NOT YET IMPLEMENTED"'

