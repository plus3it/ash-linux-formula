# Ref Doc:    STIG - RHEL 8 v1r7
# Finding ID: V-230337
# Rule ID:    SV-230337r743972_rule
# STIG ID:    RHEL-08-020015
# SRG ID:     SRG-OS-000021-GPOS-00005
#
# Finding Level: medium
#
# Rule Summary:
#       The OS must automatically lock an account until the locked account
#       is released by an administrator when three unsuccessful logon
#       attempts occur during a 15-minute time period.
#
# References:
#   CCI:
#     - CCI-000044
#
# NIST SP 800-53 :: AC-7 a
# NIST SP 800-53A :: AC-7.1 (ii)
# NIST SP 800-53 Revision 4 :: AC-7 a
#
###########################################################################
{%- set stig_id = 'RHEL-08-020015' %}
{%- set helperLoc = 'ash-linux/el8/STIGbyID/cat2/files' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}
{%- set targFile = '/etc/security/faillock.conf' %}
{%- set cfgParm = 'unlock_time' %}
{%- set cfgVal = '0' %}

script_{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stig_id }}.sh
    - cwd: /root
    - stateful: True

{%- if stig_id in skipIt %}
notify_{{ stig_id }}-skipSet:
  cmd.run:
    - name: 'printf "\nchanged=no comment=''Handler for {{ stig_id }} has been selected for skip.''\n"'
    - stateful: True
    - cwd: /root
{%- else %}
# Replace RPM-delivered content
file_{{ stig_id }}-{{ targFile }}:
  file.replace:
    - name: {{ targFile }}
    - pattern: '(^(#|)\s*)({{ cfgParm }}\s*=\s*).*'
    - repl: '{{ cfgParm }} = {{ cfgVal }}'
{%- endif %}
