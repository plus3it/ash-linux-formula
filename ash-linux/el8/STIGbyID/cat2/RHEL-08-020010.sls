# Ref Doc:    STIG - RHEL 8 v1r7
# Finding ID: V-230332
# Rule ID:    SV-230332r627750_rule
# STIG ID:    RHEL-08-020010
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
#     - CCI-000044
#   NIST SP 800-53 :: AC-7 a
#   NIST SP 800-53A :: AC-7.1 (ii)
#   NIST SP 800-53 Revision 4 :: AC-7 a
#
###########################################################################
{%- set stig_id = 'RHEL-08-020010' %}
{%- set helperLoc = 'ash-linux/el8/STIGbyID/cat2/files' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}
{%- set targFile = '/etc/security/faillock.conf' %}

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
    - pattern: ''
    - repl: ''
    - onlyif:
      - '[[ $( authselect check ) =~ "not configured with authselect" ]] '
      - 'grep --quiet pam_faillock.so /etc/pam.d/system-auth'
{%- endif %}
