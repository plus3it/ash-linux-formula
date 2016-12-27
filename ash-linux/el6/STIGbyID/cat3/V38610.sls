# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38610
# Finding ID:	V-38610
# Version:	RHEL-06-000231
# Finding Level:	Low
#
#     The SSH daemon must set a timeout count on idle sessions. This 
#     ensures a user login will be terminated as soon as the 
#     "ClientAliveCountMax" is reached.
#
#  CCI: CCI-000879
#  NIST SP 800-53 :: MA-4 e
#  NIST SP 800-53A :: MA-4.1 (vi)
#  NIST SP 800-53 Revision 4 :: MA-4 e
#
############################################################

{%- set stigId = 'V38610' %}
{%- set helperLoc = 'ash-linux/el6/STIGbyID/cat3/files' %}
{%- set checkFile = '/etc/ssh/sshd_config' %}
{%- set parmName = 'ClientAliveCountMax' %}

script_{{ stigId }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stigId }}.sh
    - cwd: /root

{%- if salt.file.search(checkFile, '^' + parmName) %}
  {%- if salt.file.search(checkFile, '^' + parmName + ' 0') %}
file_{{ stigId }}-configSet:
  cmd.run:
    - name: 'echo "{{ parmName }} already meets STIG-defined requirements"'
  {%- else %}
file_{{ stigId }}-configSet:
  file.replace:
    - name: '{{ checkFile }}'
    - pattern: '^{{ parmName }}.*$'
    - repl: '{{ parmName }} 0'
  {%- endif %}
{%- else %}
file_{{ stigId }}-configSet:
  file.append:
    - name: '{{ checkFile }}'
    - text: |
        
        # SSH service must set a session idle-timeout (per STIG V-38610)
        {{ parmName }} 0
{%- endif %}
