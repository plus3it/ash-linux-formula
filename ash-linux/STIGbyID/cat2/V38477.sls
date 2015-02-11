# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38477
# Finding ID:	V-38477
# Version:	RHEL-06-000051
# Finding Level:	Medium
#
#     Users must not be able to change passwords more than once every 24 
#     hours. Setting the minimum password age protects against users 
#     cycling back to a favorite password after satisfying the password 
#     reuse requirement.
#
# CCI: CCI-000198
# NIST SP 800-53 :: IA-5 (1) (d)
# NIST SP 800-53A :: IA-5 (1).1 (v)
# NIST SP 800-53 Revision 4 :: IA-5 (1) (d)
#
############################################################

script_V38477-describe:
  cmd.script:
    - source: salt://ash-linux/STIGbyID/cat2/files/V38477.sh

file_V38477:
  file.replace:
    - name: /etc/login.defs
    - pattern: "^PASS_MIN_DAYS.*$"
    - repl: "PASS_MIN_DAYS	1"
