# Ref Doc:    STIG - RHEL 8 v1r7
# Finding ID: V-244540
# Rule ID:    SV-244540r743869_rule
# STIG ID:    RHEL-08-020331
# SRG ID:     SRG-OS-000480-GPOS-00227
#
# Finding Level: high
#
# Rule Summary:
#       RHEL 8 must not allow blank or null passwords in the system-auth
#       file
#
# References:
#   CCI:
#     - CCI-000366
#   NIST SP 800-53 :: CM-6 b
#   NIST SP 800-53A :: CM-6.1 (iv)
#   NIST SP 800-53 Revision 4 :: CM-6 b
#
###########################################################################
{%- set stig_id = 'RHEL-08-020331' %}
{%- set helperLoc = 'ash-linux/el8/STIGbyID/cat1/files' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}
{%- set targFileList = [
  '/etc/pam.d/system-auth',
  '/etc/pam.d/password-auth',
] %}

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
  {%- for targFile in targFileList %}
{%- if salt.file.is_link(targFile) %}
  {%- set targFile = salt.cmd.run('readlink -f ' + targFile) %}
{%- endif %}
file_{{ stig_id }}-{{ targFile }}-noToks:
  file.replace:
    - name: '{{ targFile }}'
    - pattern: '^.*\s*pam_unix.so\s*nullok(\s*|)$'
    - repl: ''

file_{{ stig_id }}-{{ targFile }}-badToks:
  file.replace:
    - name: '{{ targFile }}'
    - pattern: '(^.*\s*)(nullok\s*)(.*$)'
    - repl: '\1\3\n'
    - unless:
      - 'grep -P "^.*$\s*pam_unix.so\s*nullok(\s*|)$" {{ targFile }}'
  {%- endfor %}
{%- endif %}
