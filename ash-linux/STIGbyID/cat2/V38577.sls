# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38577
# Finding ID:	V-38577
# Version:	RHEL-06-000064
# Finding Level:	Medium
#
#     The system must use a FIPS 140-2 approved cryptographic hashing 
#     algorithm for generating account password hashes (libuser.conf). 
#     Using a stronger hashing algorithm makes password cracking attacks 
#     more difficult.
#
#  CCI: CCI-000803
#  NIST SP 800-53 :: IA-7
#  NIST SP 800-53A :: IA-7.1
#  NIST SP 800-53 Revision 4 :: IA-7
#
############################################################

script_V38577-describe:
  cmd.script:
    - source: salt://STIGbyID/cat2/files/V38577.sh

# Conditional replace or append
{% if salt['file.search']('/etc/libuser.conf', '^crypt_style') %}
file_V38577-repl:
  file.replace:
    - name: /etc/libuser.conf
    - pattern: '^crypt_style.*$'
    - repl: 'crypt_style = sha512'
{% else %}
file_V38577-append:
  file.append:
    - name: /etc/libuser.conf
    - text:
      - ' '
      - '# Use SHA512 to encrypt password.'
      - 'crypt_style = sha512'
{% endif %}
