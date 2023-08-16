# STIG ID:	RHEL-07-020020
# Rule ID:	SV-86595r2_rule
# Vuln ID:	V-71971
# SRG ID:	SRG-OS-000324-GPOS-00125
# Finding Level:	medium
#
# Rule Summary:
#	The operating system must prevent non-privileged users from
#	executing privileged functions to include disabling,
#	circumventing, or altering implemented security
#	safeguards/countermeasures.
#
# CCI-002165
# CCI-002235
#    NIST SP 800-53 Revision 4 :: AC-3 (4)
#    NIST SP 800-53 Revision 4 :: AC-6 (10)
#
#################################################################
{%- set stig_id = 'RHEL-07-020020' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat2/files' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}
{%- set stig_role = 'user_u' %}
{%- set regUserGid = 1000 %}
{%- set staffUsers      = salt.pillar.get('ash-linux:lookup:sel_confine:staff_u', []) %}
{%- set sysadmUsers     = salt.pillar.get('ash-linux:lookup:sel_confine:sysadm_u', []) %}
{%- set unconfinedUsers = salt.pillar.get('ash-linux:lookup:sel_confine:unconfined_u', []) %}
{%- set nulUsers = [] %}

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
    {%- set userInfo = salt.user.info(userName) %}
    {%- if userInfo.gid >= regUserGid %}

      {%- if userName in staffUsers %}
Map {{ userName }} to staff_u:
  cmd.run:
    - name: 'semanage login {{ userName }} -a -s staff_u'
      {%- endif %}

      {%- if userName in sysadmUsers %}
Map {{ userName }} to sysadm_u:
  cmd.run:
    - name: 'semanage login {{ userName }} -a -s sysadm_u'
      {%- endif %}

      {%- if userName in unconfinedUsers %}
Map {{ userName }} to unconfined_u:
  cmd.run:
    - name: 'semanage login {{ userName }} -a -s unconfined_u'
      {%- endif %}

    {%- endif %}
  {%- endfor %}
{%- endif %}
