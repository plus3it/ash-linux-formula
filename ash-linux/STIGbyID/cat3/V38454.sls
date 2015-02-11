# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38454
# Finding ID:	V-38454
# Version:	RHEL-06-000516
# Finding Level:	Low
#
#     Ownership of system binaries and configuration files that is 
#     incorrect could allow an unauthorized user to gain privileges that 
#     they should not have. The ownership set by the vendor should be 
#     maintained. Any deviations from this baseline should be investigated. 
#
#  CCI: CCI-000366
#  NIST SP 800-53 :: CM-6 b
#  NIST SP 800-53A :: CM-6.1 (iv)
#  NIST SP 800-53 Revision 4 :: CM-6 b
#
############################################################

script_V38454-describe:
  cmd.script:
    - source: salt://ash-linux/STIGbyID/cat3/files/V38454.sh

# Probably need to replace this with custom module...
script_V38454-Verfiy:
  cmd.script:
    - source: salt://ash-linux/STIGbyID/cat3/files/V38454-helper.sh
