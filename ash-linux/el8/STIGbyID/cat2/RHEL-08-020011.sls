# Ref Doc:    STIG - RHEL 8 v1r7
# Finding ID: V-230333
# Rule ID:    SV-230333r743966_rule
# STIG ID:    RHEL-08-020011
# SRG ID:     SRG-OS-000021-GPOS-00005
#
# Finding Level: medium
#
# Rule Summary:
#       RHEL 8 must automatically lock an account when three unsuccessful
#       logon attempts occur.
#
# References:
#   CCI:
#     - CCI-000200
#   NIST SP 800-53 :: IA-5 (1) (e)
#   NIST SP 800-53A :: IA-5 (1).1 (v)
#   NIST SP 800-53 Revision 4 :: IA-5 (1) (e)
#
###########################################################################
{%- set stig_id = 'RHEL-08-020011' %}
{%- set helperLoc = 'ash-linux/el8/STIGbyID/cat2/files' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}
{%- set targFile = '/etc/security/faillock.conf' %}
{%- set cfgParm = 'deny' %}
{%- set cfgVal = '3' %}

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
# Replace RPM-delivered content
file_{{ stig_id }}-{{ targFile }}_fromRpm:
  file.replace:
    - name: {{ targFile }}
    - pattern: '(^# Deny access.*\n.*\n# The default is.*\n# deny.*$)'
    - repl: '\1\n{{ cfgParm }} = {{ cfgVal }}'
    - unless:
      - 'rpm -qVf {{ targFile }} | grep -qE "([mM]|\.)5.*{{ targFile }}"'
{%- endif %}
