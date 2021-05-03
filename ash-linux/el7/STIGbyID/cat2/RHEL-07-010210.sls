# STIG ID:	RHEL-07-010210
# Rule ID:	SV-86545r2_rule
# Vuln ID:	V-71921
# SRG ID:	SRG-OS-000073-GPOS-00041
# Finding Level:	medium
#
# Rule Summary:
#	The shadow file must be configured to store only encrypted
#	representations of passwords.
#
# CCI-000196
#    NIST SP 800-53 :: IA-5 (1) (c)
#    NIST SP 800-53A :: IA-5 (1).1 (v)
#    NIST SP 800-53 Revision 4 :: IA-5 (1) (c)
#
#################################################################
{%- set stig_id = 'RHEL-07-010210' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat2/files' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}
{%- set targFile = '/etc/login.defs' %}
{%- set searchRoot = 'ENCRYPT_METHOD' %}

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
    - repl: '{{ searchRoot }} SHA512'
  {%- else %}
file_{{ stig_id }}-{{ targFile }}:
  file.append:
    - name: '{{ targFile }}'
    - text: |-
        # Inserted per STIG {{ stig_id }}
        {{ searchRoot }} SHA512
  {%- endif %}
{%- endif %}
