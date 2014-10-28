# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38663
# Finding ID:	V-38663
# Version:	RHEL-06-000278
# Finding Level:	Medium
#
#     The system package management tool must verify permissions on all 
#     files and directories associated with the audit package. Permissions 
#     on audit binaries and configuration files that are too generous could 
#     allow an unauthorized user to gain privileges that they should not 
#     have. The permissions set by the vendor should be ...
#
############################################################

script_V38663-describe:
  cmd.script:
  - source: salt://STIGbyID/cat2/files/V38663.sh

# NEED TO INVESTIGATE USE OF pkg.verify MODULE

cmd_V38663-NotImplemented:
  cmd.run:
  - name: 'echo "NOT YET IMPLEMENTED"'
