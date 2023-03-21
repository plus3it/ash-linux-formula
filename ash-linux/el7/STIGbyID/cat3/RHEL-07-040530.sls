# Finding ID:	RHEL-07-040530
# Version:	SV-204605r603261_rule
# SRG ID:	SRG-OS-000480-GPOS-00227
# Finding Level:	low
#
# Rule Summary:
#	The operating system must display the date and time of
#   the last successful account logon upon logon.
#
# CCI-000366
#
#################################################################
{%- set stig_id = 'RHEL-07-040530' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat3/files' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}
{%- set pamFile = '/etc/pam.d/postlogin'%}
{%- if salt.file.is_link(pamFile) %}
  {%- set pamFile = pamFile + '-ac' %}
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
file-add{{ stig_id }}-{{ pamFile }}:
  file.replace:
    - name: {{ pamFile }}
    - pattern: '^(?P<srctok>(|\s*)session\s*\[default=\d]\s*pam_lastlog.so.*$)'
    - repl: '\g<srctok>\nsession     required      pam_lastlog.so showfailed'
    - require:
      - file: 'file-modify_{{ stig_id }}-{{ pamFile }}'
    - unless:
      - 'grep -P "^(|\s*)session\s*required\s*pam_lastlog.so.*(showfailed){1}$" {{ pamFile }}'

file-modify_{{ stig_id }}-{{ pamFile }}:
  file.replace:
    - name: {{ pamFile }}
    - onlyif:
      - 'grep -P "^(|\s*)session\s*(optional|required)\s*pam_lastlog.so.*(showfailed){1}$" {{ pamFile }}'
    - pattern: '^(|\s*)(session\s*){1}optional(\s*pam_lastlog.so\s*){1}(.*)(\s*showfailed)(\s*.*$)'
    - repl: '\g<1>\g<2>required\g<3>\g<4>\g<5>\g<6>'
{%- endif %}
