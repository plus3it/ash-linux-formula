# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38637
# Finding ID:	V-38637
# Version:	RHEL-06-000281
# Finding Level:	Medium
#
#     The system package management tool must verify contents of all files 
#     associated with the audit package. The hash on important files like 
#     audit system executables should match the information given by the 
#     RPM database. Audit executables with erroneous hashes could be a sign 
#     of nefarious activity on the ...
#
############################################################

script_V38637-describe:
  cmd.script:
    - source: salt://ash-linux/STIGbyID/cat2/files/V38637.sh
    - cwd: '/root'

script_V38637-tamperCheck:
  cmd.script:
    - source: salt://ash-linux/STIGbyID/cat2/files/V38637-helper.sh
    - cwd: '/root'
