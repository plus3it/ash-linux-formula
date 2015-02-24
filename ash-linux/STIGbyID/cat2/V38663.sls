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
#  CCI: CCI-001493
#  NIST SP 800-53 :: AU-9
#  NIST SP 800-53A :: AU-9.1
#  NIST SP 800-53 Revision 4 :: AU-9
#
############################################################

script_V38663-describe:
  cmd.script:
    - source: salt://ash-linux/STIGbyID/cat2/files/V38663.sh
    - cwd: '/root'

# NEED TO INVESTIGATE USE OF pkg.verify MODULE

script_V38663-helper:
  cmd.script:
    - source: salt://ash-linux/STIGbyID/cat2/files/V38663-helper.sh
    - cwd: '/root'
