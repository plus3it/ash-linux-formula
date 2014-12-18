# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38574
# Finding ID:	V-38574
# Version:	RHEL-06-000062
# Finding Level:	Medium
#
#     The system must use a FIPS 140-2 approved cryptographic hashing 
#     algorithm for generating account password hashes (system-auth). Using 
#     a stronger hashing algorithm makes password cracking attacks more 
#     difficult.
#
#  CCI: CCI-000803
#  NIST SP 800-53 :: IA-7
#  NIST SP 800-53A :: IA-7.1
#  NIST SP 800-53 Revision 4 :: IA-7
#
############################################################

script_V38574-describe:
  cmd.script:
  - source: salt://STIGbyID/cat2/files/V38574.sh

file_V38574-repl:
  file.replace:
  - name: /etc/sysconfig/authconfig
  - pattern: '^PASSWDALGORITHM.*$'
  - repl: 'PASSWDALGORITHM=sha512'
