# Ref Doc:    STIG - RHEL 8 v1r7
# Finding ID: V-230381
# Rule ID:    SV-230381r627750_rule
# STIG ID:    RHEL-08-020340
# SRG ID:     SRG-OS-000480-GPOS-00227
#
# Finding Level: low
#
# Rule Summary:
#       The OS must display the date and time of the last successful
#       account logon upon logon
#
# References:
#   CCI:
#     - CCI-000366
#   NIST SP 800-53 :: CM-6 b
#   NIST SP 800-53A :: CM-6.1 (iv)
#   NIST SP 800-53 Revision 4 :: CM-6 b
#
###########################################################################
{%- set stig_id = 'RHEL-08-020340' %}
{%- set helperLoc = 'ash-linux/el8/STIGbyID/cat3/files' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}
{%- set targFile = '/etc/pam.d/postlogin' %}

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
file_{{ stig_id }}_{{ targFile }}:
  file.replace:
    - name: '{{ targFile }}'
    - pattern: '(^\s*session\s*)(optional)(\s*pam_lastlog.so\s*.*)(silent\s*)(.*$)'
    - repl: '# Set per STIG-ID {{ stig_id }}\n\1required\3\5'
{%- endif %}

