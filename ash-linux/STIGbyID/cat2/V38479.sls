# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38479
# Finding ID:	V-38479
# Version:	RHEL-06-000053
# Finding Level:	Medium
#
#     User passwords must be changed at least every 60 days. Setting the 
#     password maximum age ensures users are required to periodically 
#     change their passwords. This could possibly decrease the utility of a 
#     stolen password. Requiring shorter password lifetimes ...
#
#  CCI: CCI-000199
#  NIST SP 800-53 :: IA-5 (1) (d)
#  NIST SP 800-53A :: IA-5 (1).1 (v)
#  NIST SP 800-53 Revision 4 :: IA-5 (1) (d)
#
############################################################

script_V38479-describe:
  cmd.script:
    - source: salt://ash-linux/STIGbyID/cat2/files/V38479.sh
    - cwd: '/root'

file_V38479:
  file.replace:
    - name: /etc/login.defs
    - pattern: "^PASS_MAX_DAYS.*$"
    - repl: "PASS_MAX_DAYS	60"
