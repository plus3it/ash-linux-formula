# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38447
# Finding ID:	V-38447
# Version:	RHEL-06-000519
# Finding Level:	Low
#
#     The system package management tool must verify contents of all files 
#     associated with packages. The hash on important files like system 
#     executables should match the information given by the RPM database. 
#     Executables with erroneous hashes could be a sign of nefarious 
#     activity on the system.
#
#  CCI: CCI-000366
#  NIST SP 800-53 :: CM-6 b
#  NIST SP 800-53A :: CM-6.1 (iv)
#  NIST SP 800-53 Revision 4 :: CM-6 b
#
############################################################

script_V38447-describe:
  cmd.script:
    - source: salt://ash-linux/STIGbyID/cat3/files/V38447.sh
    - cwd: /root
    - cwd: /root

# Need to replace this with custom module...
script_V38447-Verfiy:
  cmd.script:
    - source: salt://ash-linux/STIGbyID/cat3/files/V38447-helper.sh
    - cwd: /root
    - cwd: /root
