# Finding ID:	RHEL-07-010210
# Version:	RHEL-07-010210_rule
# SRG ID:	SRG-OS-000075-GPOS-00043
# Finding Level:	medium
# 
# Rule Summary:
#	Passwords must be restricted to a 24 hours/1 day minimum lifetime.
#
# CCI-000198 
#    NIST SP 800-53 :: IA-5 (1) (d) 
#    NIST SP 800-53A :: IA-5 (1).1 (v) 
#    NIST SP 800-53 Revision 4 :: IA-5 (1) (d) 
#
#################################################################
{%- set stig_id = 'RHEL-07-010210' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat2/files' %}
{%- set targExp = 1 %}
{%- set goodUsers = [] %}

script_{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stig_id }}.sh
    - cwd: /root

{%- for userName in salt.user.list_users() %}
{%- set shadowInfo = salt.shadow.info(userName) %}
{%- set userPasswd = shadowInfo.passwd %}
{%- set passwdMin = shadowInfo.min %}
  {%- if (
          userPasswd.startswith("$") and
          passwdMin < targExp 
         )
    %}
{%- do goodUsers.append(userName) %}
notify_{{ stig_id }}-{{ userName }}:
  cmd.run:
    - name: 'printf "\nchanged=no comment=''{{ userName }} min-change value ({{ passwdMin }}) is less than {{ targExp }}. Changing...''\n"'
    - cwd: /root
    - stateful: True

setmin_{{ stig_id }}-{{ userName }}:
  module.run:
    - name: shadow.set_mindays
    - m_name: '{{ userName }}'
    - mindays: {{ targExp }}
    - require: 
      - cmd: notify_{{ stig_id }}-{{ userName }}

  {%- endif %}
{%- endfor %}

{%- if not goodUsers %}
notify_{{ stig_id }}-FoundNone:
  cmd.run:
    - name: 'printf "\nchanged=no comment=''Found no users with non-compliant minimum password lifetime.''\n"'
    - cwd: /root
    - stateful: True
{%- endif %}
