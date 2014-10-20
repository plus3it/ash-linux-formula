# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38522
# Finding ID:	V-38522
# Version:	RHEL-06-000167
# Finding Level:	Medium
#
#     Arbitrary changes to the system time can be used to obfuscate 
#     nefarious activities in log files, as well as to confuse network 
#     services that are highly dependent upon an accurate system time (such 
#     as sshd). All changes to the system time should be audited. 
#
############################################################################

script_V38522-describe:
  cmd.script:
  - source: salt://STIGbyID/cat2/files/V38522.sh

