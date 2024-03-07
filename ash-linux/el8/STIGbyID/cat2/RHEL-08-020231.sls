
# Ref Doc:    STIG - RHEL 8 v1r9
# Finding ID: V-230370
# Rule ID:    SV-230370r627750_rule
# STIG ID:    RHEL-08-020231
# SRG ID:     SRG-OS-000078-GPOS-00046
#
# Finding Level: medium
#
# Rule Summary:
#       Passwords for new users must have a minimum of 15 characters
#
# References:
#   CCI:
#     - CCI-000205
#   NIST SP 800-53 :: IA-5 (1) (a)
#   NIST SP 800-53A :: IA-5 (1).1 (i)
#   NIST SP 800-53 Revision 4 :: IA-5 (1) (a)
#
###########################################################################
{%- set stig_id = 'RHEL-08-020231' %}
{%- set helperLoc = tpldir ~ '/files' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}
{%- set targFile = '/etc/login.defs' %}

script_{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stig_id }}.sh
    - stateful: True
    - cwd: /root

{%- if stig_id in skipIt %}
notify_{{ stig_id }}-skipSet:
  cmd.run:
    - name: 'printf "\nchanged=no comment=''Handler for {{ stig_id }} has been selected for skip.''\n"'
    - stateful: True
    - cwd: /root
{%- else %}
file_{{ stig_id }}-{{ targFile }}_poolDirectives:
  file.replace:
    - name: '{{ targFile }}'
    - append_if_not_found: True
    - pattern: '(^PASS_MIN_LEN)\s*[0-9]*.*$'
    - repl: '\1 15'
{%- endif %}
