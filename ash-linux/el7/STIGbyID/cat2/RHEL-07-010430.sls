# STIG ID:	RHEL-07-010430
# Rule ID:	SV-86575r2_rule
# Vuln ID:	V-71951
# SRG ID:	SRG-OS-000480-GPOS-00226
# Finding Level:	medium
#
# Rule Summary:
#	The delay between logon prompts following a failed console
#	logon attempt must be at least four seconds.
#
# CCI-000366
#    NIST SP 800-53 :: CM-6 b
#    NIST SP 800-53A :: CM-6.1 (iv)
#    NIST SP 800-53 Revision 4 :: CM-6 b
#
#################################################################
{%- set stig_id = 'RHEL-07-010430' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat2/files' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}
{%- set targFile = '/etc/login.defs' %}
{%- set searchRoot = 'FAIL_DELAY' %}
{%- set targVal = '4' %}

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
    - repl: '{{ searchRoot }}	{{ targVal }}'
  {%- else %}
file_{{ stig_id }}-{{ targFile }}:
  file.append:
    - name: '{{ targFile }}'
    - text: |-
        # Inserted per STIG {{ stig_id }}
        {{ searchRoot }}	{{ targVal }}
  {%- endif %}
{%- endif %}
