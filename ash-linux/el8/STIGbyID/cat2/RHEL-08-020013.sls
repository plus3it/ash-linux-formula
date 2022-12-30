# Ref Doc:    STIG - RHEL 8 v1r7
# Finding ID: V-230335
# Rule ID:    SV-230335r743969_rule
# STIG ID:    RHEL-08-020013
# SRG ID:     SRG-OS-000021-GPOS-00005
#
# Finding Level: medium
#
# Rule Summary:
#       RHEL 8 must automatically lock an account when three unsuccessful
#       logon attempts occur within a 15-minute time period.
#
# References:
#   CCI:
#     - CCI-000044
#   NIST SP 800-53 :: AC-7 a
#   NIST SP 800-53A :: AC-7.1 (ii)
#   NIST SP 800-53 Revision 4 :: AC-7 a
#
###########################################################################
{%- set stig_id = 'RHEL-08-020013' %}
{%- set helperLoc = 'ash-linux/el8/STIGbyID/cat2/files' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}
{%- set targFile = '/etc/security/faillock.conf' %}
{%- set cfgParm = 'fail_interval' %}
{%- set cfgVal  = '900' %}

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
file_{{ stig_id }}-{{ targFile }}:
  file.replace:
    - name: {{ targFile }}
    - pattern: '(^# The default is .*\n#\s*fail_interval\s*=\s*\d.*$)'
    - repl: '\1\n# Set per STIG-ID {{ stig_id }}\n{{ cfgParm }} = {{ cfgVal }}'
    - unless: 'grep -E "^\s*{{ cfgParm }}(\s*=\s*){{ cfgVal }}" {{ targFile }}'
{%- endif %}

