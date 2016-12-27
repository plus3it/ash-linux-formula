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
{%- set stigId = 'V38577' %}
{%- set helperLoc = 'ash-linux/el6/STIGbyID/cat2/files' %}
{%- set chkFile = '/etc/libuser.conf' %}
{%- set parmName = 'crypt_style' %}
{%- set parmVal = 'sha512' %}

script_V38577-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/V38577.sh
    - cwd: '/root'

# Conditional replace or append
{%- if salt.file.search(chkFile, '^' + parmName) %}
file_V38577-repl:
  file.replace:
    - name: '{{ chkFile }}'
    - pattern: '^{{ parmName }}.*$'
    - repl: '{{ parmName }} = sha512'
{%- else %}
file_V38577-append:
  file.append:
    - name: '{{ chkFile }}'
    - text:
      - ' '
      - '# Use SHA512 to encrypt password.'
      - '{{ parmName }} = sha512'
{%- endif %}
