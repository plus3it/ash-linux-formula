# Ref Doc:    STIG - RHEL 8 v1r10
# Finding ID: V-244533
# Rule ID:    SV-244533r743848_rule
# STIG ID:    RHEL-08-020025
# SRG ID:     SRG-OS-000021-GPOS-00005
#             SRG-OS-000329-GPOS-00128
#
# Finding Level: medium
#
# Rule Summary:
#       The OS must configure the use of the pam_faillock.so module in the
#       /etc/pam.d/system-auth file.
#
# References:
#   CCI:
#     - CCI-000044
#       - NIST SP 800-53 :: AC-7 a
#       - NIST SP 800-53A :: AC-7.1 (ii)
#       - NIST SP 800-53 Revision 4 :: AC-7 a
#
###########################################################################
{%- set stig_id = 'RHEL-08-020025' %}
{%- set helperLoc = 'ash-linux/el8/STIGbyID/cat2/files' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}
{%- set targFile = '/etc/pam.d/system-auth' %}
{%- if salt.file.is_link(targFile) %}
  {%- set targFile = salt.cmd.run('readlink -f ' + targFile) %}
{%- endif %}

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
Ensure auth pam_faillock.so authfail before pam_unix.so:
  file.replace:
    - name: '{{ targFile }}'
    - pattern: '(^auth\s*(sufficient|\[.*])\s*pam_unix.so.*)'
    - repl: 'auth        required                                     pam_faillock.so authfail\n\1'
    - unless:
      - '[[ $( grep -Pq "^auth\s*required\s*pam_faillock.so\s*authfail" {{ targFile }} )$? -eq 0 ]]'

Ensure auth pam_faillock.so preauth before pam_faillock.so authfail:
  file.replace:
    - name: '{{ targFile }}'
    - pattern: '(^auth\s*required\s*pam_faillock.so authfail)'
    - repl: 'auth        required                                     pam_faillock.so preauth\n\1'
    - require:
      - file: 'Ensure auth pam_faillock.so authfail before pam_unix.so'
    - unless:
      - '[[ $( grep -Pq "^auth\s*required\s*pam_faillock.so\s*preauth" {{ targFile }} )$? -eq 0 ]]'

Ensure accunt pam_faillock.so before pam_unix.so:
  file.replace:
    - name: '{{ targFile }}'
    - pattern: '(^account\s*required\s*pam_unix.so.*)'
    - repl: 'account     required                                     pam_faillock.so\n\1'
    - unless:
      - '[[ $( grep -Pq "^account\s*required\s*pam_faillock.so" /etc/authselect/system-auth )$? -eq 0 ]]'
{%- endif %}

