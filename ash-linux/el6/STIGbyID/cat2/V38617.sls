# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38617
# Finding ID:	V-38617
# Version:	RHEL-06-000243
# Finding Level:	Medium
#
#     The SSH daemon must be configured to use only FIPS 140-2 approved 
#     ciphers. Approved algorithms should impart some level of confidence 
#     in their implementation. These are also required for compliance.
#
#  CCI: CCI-001144
#  NIST SP 800-53 :: SC-13
#  NIST SP 800-53A :: SC-13.1
#
############################################################

{%- set stigId = 'V38617' %}
{%- set helperLoc = 'ash-linux/el6/STIGbyID/cat2/files' %}
{%- set cfgFile = '/etc/ssh/sshd_config' %}
{%- set parmName = 'Ciphers' %}
{%- set parmVal = 'aes128-ctr,aes192-ctr,aes256-ctr,aes128-cbc,3des-cbc,aes192-cbc,aes256-cbc' %}

script_{{ stigId }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stigId }}.sh
    - cwd: '/root'

{%- if salt.file.search(cfgFile, '^' + parmName)
 %}
file_{{ stigId }}-repl:
  file.replace:
    - name: '{{ cfgFile }}'
    - pattern: '^{{ parmName }}.*$'
    - repl: '{{ parmName }} {{parmVal }}'
{%- else %}
file_{{ stigId }}-append:
  file.append:
    - name: '{{ cfgFile }}'
    - text:
      - ' '
      - '# SSH service must allow only FIPS 140-2 ciphers (per STIG V-38617)'
      - '{{ parmName }} {{ parmVal }}'
{%- endif %}

