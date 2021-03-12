# STIG ID:	RHEL-07-010220
# Rule ID:	SV-86547r3_rule
# Vuln ID:	V-71923
# SRG ID:	SRG-OS-000073-GPOS-00041
# Finding Level:	medium
#
# Rule Summary:
#	User and group account administration utilities must be
#	configured to store only encrypted representations of
#	passwords.
#
# CCI-000196
#    NIST SP 800-53 :: IA-5 (1) (c)
#    NIST SP 800-53A :: IA-5 (1).1 (v)
#    NIST SP 800-53 Revision 4 :: IA-5 (1) (c)
#
#################################################################
{%- set stig_id = 'RHEL-07-010220' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat2/files' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}
{%- set targFile = '/etc/libuser.conf' %}
{%- set searchRoot = 'crypt_style' %}

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
  {%- if salt.file.search(targFile, '^' + searchRoot) %}
file_{{ stig_id }}-{{ targFile }}:
  file.replace:
    - name: '{{ targFile }}'
    - pattern: '^{{ searchRoot }}.*$'
    - repl: '{{ searchRoot }} = sha512'
  {%- else %}
file_{{ stig_id }}-{{ targFile }}:
  file.replace:
    - name: '{{ targFile }}'
    - pattern: '^(?P<srctok>^\[defaults\].*$)'
    - repl: '\g<srctok>\n{{ searchRoot }} = sha512'
  {%- endif %}
{%- endif %}
