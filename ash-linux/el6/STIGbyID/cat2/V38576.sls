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

{%- set stigId = 'V38576' %}
{%- set helperLoc = 'ash-linux/el6/STIGbyID/cat2/files' %}
{%- set chkFile = '/etc/login.defs' %}
{%- set parmName = 'ENCRYPT_METHOD' %}
{%- set parmVal = 'SHA512' %}

script_{{ stigId }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stigId }}.sh
    - cwd: '/root'

# Conditional replace or append
{%- if salt.file.search(chkFile, '^' + parmName) %}
file_{{ stigId }}-repl:
  file.replace:
    - name: '{{ chkFile }}'
    - pattern: '^ENCRYPT_METHOD.*$'
    - repl: '{{ parmName }} {{ parmVal }}'
{%- else %}
file_{{ stigId }}-append:
  file.append:
    - name: '{{ chkFile }}'
    - text:
      - ' '
      - '# Use {{ parmVal }} to encrypt password.'
      - '{{ parmName }} {{ parmVal }}'
{%- endif %}
