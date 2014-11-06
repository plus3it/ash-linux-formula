# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38452
# Finding ID:	V-38452
# Version:	RHEL-06-000518
# Finding Level:	Low
#
#     Permissions on system binaries and configuration files that are too 
#     generous could allow an unauthorized user to gain privileges that 
#     they should not have. The permissions set by the vendor should be 
#     maintained. Any deviations from this baseline should be investigated. 
#
#  CCI: CCI-000366
#  NIST SP 800-53 :: CM-6 b
#  NIST SP 800-53A :: CM-6.1 (iv)
#  NIST SP 800-53 Revision 4 :: CM-6 b
#
############################################################

script_V38452-describe:
  cmd.script:
  - source: salt://STIGbyID/cat3/files/V38452.sh

# Need to replace this with custom module...
script_V38452-Verfiy:
  cmd.script:
  - source: salt://STIGbyID/cat3/files/V38452-helper.sh

