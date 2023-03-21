# STIG ID:	RHEL-07-010270
# Rule ID:	SV-86557r3_rule
# Vuln ID:	V-71933
# SRG ID:	SRG-OS-000077-GPOS-00045
# Finding Level:	medium
#
# Rule Summary:
#	Passwords must be prohibited from reuse for a minimum of five generations.
#
# CCI-000200
#    NIST SP 800-53 :: IA-5 (1) (e)
#    NIST SP 800-53A :: IA-5 (1).1 (v)
#    NIST SP 800-53 Revision 4 :: IA-5 (1) (e)
#
#################################################################
{%- set stig_id = 'RHEL-07-010270' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat2/files' %}
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
      {%- set targFile = targFile + '-ac' %}
    {%- endif %}
file-add_{{ stig_id }}-{{ targFile }}:
  file.replace:
    - name: {{ targFile }}
    - pattern: '^(?P<srctok>(|\s*)password\s*sufficient\s*pam_unix.so.*$)'
    - repl: '\g<srctok>\npassword    requisite     pam_pwhistory.so use_authtok remember=5 retry=3'
    - unless:
      - 'grep -P "^(|\s*)password\s*requisite\s*pam_pwhistory.so.*$" {{ targFile }}'
file-modify_{{ stig_id }}-{{ targFile }}:
  file.replace:
    - name: {{ targFile }}
    - pattern: '^(|\s*)(password\s*sufficient\s*pam_pwhistory.so)(.*)'
    - repl: 'password    requisite     pam_pwhistory.so use_authtok remember=5 retry=3'
    - onlyif:
      - 'grep -P "^(|\s*)password\s*requisite\s*pam_pwhistory.so.*$" {{ targFile }}'
  {%- endfor %}
{%- endif %}
