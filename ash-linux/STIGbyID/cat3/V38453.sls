# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38453
# Finding ID:	V-38453
# Version:	RHEL-06-000517
# Finding Level:	Low
#
#     Group-ownership of system binaries and configuration files that is 
#     incorrect could allow an unauthorized user to gain privileges that 
#     they should not have. The group-ownership set by the vendor should be 
#     maintained. Any deviations from this baseline should be investigated. 
#
#  CCI: CCI-000366
#  NIST SP 800-53 :: CM-6 b
#  NIST SP 800-53A :: CM-6.1 (iv)
#  NIST SP 800-53 Revision 4 :: CM-6 b
#
############################################################

script_V38453-describe:
  cmd.script:
    - source: salt://ash-linux/STIGbyID/cat3/files/V38453.sh
    - cwd: /root
    - cwd: /root

# Probably need to replace this with custom module...
script_V38453-Verfiy:
  cmd.script:
    - source: salt://ash-linux/STIGbyID/cat3/files/V38453-helper.sh
    - cwd: /root
    - cwd: /root
