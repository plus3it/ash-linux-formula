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

# Update /etc/sysconfig/authconfig
file_V38574-repl:
  file.replace:
    - name: /etc/sysconfig/authconfig
    - pattern: '^PASSWDALGORITHM.*$'
    - repl: 'PASSWDALGORITHM=sha512'

# Update pam_unix.so settings in /etc/pam.d/system-auth
{% set checkFile = '/etc/pam.d/system-auth-ac' %}
{% set parmName = 'sha512' %}

{% if not salt['file.file_exists'](checkFile) %}
cmd_V38482-linkSysauth:
  cmd.run:
    - name: '/usr/sbin/authconfig --update'
{% endif %}

{% if salt['file.search'](checkFile, ' pam_unix.so ') %}
  # See if SHA512 already set
  {% if salt['file.search'](checkFile, ' ' + parmName) %}
set_V38574-sha512:
  cmd.run:
    - name: 'echo "Passwords already require SHA512 encryption"'
  # If set to md5, switch to sha512
  {% elif salt['file.search'](checkFile, '^[ 	]*password[ 	]*sufficient[ 	]*pam_unix.so.* md5 ') %}
set_V38574-sha512:
  file.replace:
    - name: {{ checkFile }}
    - pattern: ' md5 '
    - repl: ' {{ parmName }} '
  # Tack on sha512 token if necessary
  {% else %}
set_V38574-sha512:
  file.replace:
    - name: {{ checkFile }}
    - pattern: '^(?P<srctok>password[ 	]*sufficient[ 	]*pam_unix.so.*$)'
    - repl: '\g<srctok> {{ parmName }}'
  {% endif %}
{% endif %}
