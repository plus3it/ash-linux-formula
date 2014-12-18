# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38576
# Finding ID:	V-38576
# Version:	RHEL-06-000063
# Finding Level:	Medium
#
#     The system must use a FIPS 140-2 approved cryptographic hashing 
#     algorithm for generating account password hashes (login.defs). Using 
#     a stronger hashing algorithm makes password cracking attacks more 
#     difficult.
#
#  CCI: CCI-000803
#  NIST SP 800-53 :: IA-7
#  NIST SP 800-53A :: IA-7.1
#  NIST SP 800-53 Revision 4 :: IA-7
#
############################################################

script_V38576-describe:
  cmd.script:
  - source: salt://STIGbyID/cat2/files/V38576.sh

# Conditional replace or append
{% if salt['file.search']('/etc/login.defs', '^ENCRYPT_METHOD') %}
file_V38576-repl:
  file.replace:
  - name: /etc/login.defs
  - pattern: '^ENCRYPT_METHOD.*$'
  - repl: 'ENCRYPT_METHOD SHA512'
{% else %}
file_V38576-append:
  file.append:
  - name: /etc/login.defs
  - text:
    - ' '
    - '# Use SHA512 to encrypt password.'
    - 'ENCRYPT_METHOD SHA512'
{% endif %}

