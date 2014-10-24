# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38469
# Finding ID:	V-38469
# Version:	RHEL-06-000047
# Finding Level:	Medium
#
#     All system command files must have mode 0755 or less permissive. 
#     System binaries are executed by privileged users, as well as system 
#     services, and restrictive permissions are necessary to ensure 
#     execution of these programs cannot be co-opted.
#
############################################################

script_V38469-describe:
  cmd.script:
  - source: salt://STIGbyID/cat2/files/V38469.sh

cmd_V38469-NotImplemented:
  cmd.run:
  - name: 'echo "NOT YET IMPLEMENTED"'
