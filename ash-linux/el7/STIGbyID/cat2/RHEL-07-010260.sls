# STIG ID:	RHEL-07-010260
# Rule ID:	SV-86555r3_rule
# Vuln ID:	V-71931
# SRG ID:	SRG-OS-000076-GPOS-00044
# Finding Level:	medium
#
# Rule Summary:
#	Existing passwords must be restricted to a 60-day maximum lifetime.
#
# CCI-000199
#    NIST SP 800-53 :: IA-5 (1) (d)
#    NIST SP 800-53A :: IA-5 (1).1 (v)
#    NIST SP 800-53 Revision 4 :: IA-5 (1) (d)
#
#################################################################
{%- set stig_id = 'RHEL-07-010260' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat2/files' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}
{%- set targExp = 60 %}
{%- set goodUsers = [] %}

script_{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stig_id }}.sh
    - cwd: /root

{%- if stig_id in skipIt %}
notify_{{ stig_id }}-skipSet:
  cmd.run:
    - name: 'printf "\nchanged=no comment=''Handler for {{ stig_id }} has been selected for skip.''\n"'
    - stateful: True
    - cwd: /root
{%- else %}
  {%- for userName in salt.user.list_users() %}
  {%- set shadowInfo = salt.shadow.info(userName) %}
  {%- set userPasswd = shadowInfo.passwd %}
  {%- set passwdMax = shadowInfo.max %}
    {%- if (
          userPasswd.startswith("$") and
          passwdMax > targExp
         )
    %}
  {%- do goodUsers.append(userName) %}
notify_{{ stig_id }}-{{ userName }}:
  cmd.run:
    - name: 'printf "\nchanged=no comment=''{{ userName }} max-change value ({{ passwdMax }}) is less than {{ targExp }}. Changing...''\n"'
    - cwd: /root
    - stateful: True

setmax_{{ stig_id }}-{{ userName }}:
  module.run:
    - name: shadow.set_maxdays
    - m_name: '{{ userName }}'
    - maxdays: {{ targExp }}
    - require:
      - cmd: notify_{{ stig_id }}-{{ userName }}

    {%- endif %}
  {%- endfor %}

  {%- if not goodUsers %}
notify_{{ stig_id }}-FoundNone:
  cmd.run:
    - name: 'printf "\nchanged=no comment=''Found no users with non-compliant maximum password lifetime.''\n"'
    - cwd: /root
    - stateful: True
  {%- endif %}
{%- endif %}
