# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38616
# Finding ID:	V-38616
# Version:	RHEL-06-000241
# Finding Level:	Low
#
#     The SSH daemon must not permit user environment settings. SSH 
#     environment options potentially allow users to bypass access 
#     restriction in some configurations.
#
############################################################

{%- set stigId = 'V38616' %}
{%- set helperLoc = 'ash-linux/el6/STIGbyID/cat3/files' %}
{%- set cfgFile = '/etc/ssh/sshd_config' %}
{%- set parmName = 'PermitUserEnvironment' %}
{%- set parmVal = 'no' %}

script_{{ stigId }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stigId }}.sh
    - cwd: /root

{%- if salt.file.search(cfgFile, '^' + parmName + ' ' + parmVal) %}
file_{{ stigId }}-configExists:
  cmd.run:
    - name: 'echo "{{ parmName }} already meets STIG-defined requirements"'
{%- endif %}

file{{ stigId }}-comment:
  file.comment:
    - name: '{{ cfgFile }}'
    - regex: '^{{ parmName }}'
    - unless: 'grep -E "^{{ parmName }}" {{ cfgFile }} && grep -E "^{{ parmName }} {{ parmVal }}" {{ cfgFile }}'

file_{{ stigId }}-configSet:
  file.append:
    - name: '{{ cfgFile }}'
    - text: |
        
        # SSH service must not allow setting of user environment options (per STIG V-38616)
        {{ parmName }} {{ parmVal }}
    - unless: 'grep -E "^{{ parmName }} {{ parmVal }}" {{ cfgFile }}'
