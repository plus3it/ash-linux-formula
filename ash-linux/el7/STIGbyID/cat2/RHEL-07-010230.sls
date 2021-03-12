# STIG ID:	RHEL-07-010230
# Rule ID:	SV-86549r2_rule
# Vuln ID:	V-71925
# SRG ID:	SRG-OS-000075-GPOS-00043
# Finding Level:	medium
#
# Rule Summary:
#	Passwords for new users must be restricted to a 24 hours/1 day
#	minimum lifetime.
#
# CCI-000198
#    NIST SP 800-53 :: IA-5 (1) (d)
#    NIST SP 800-53A :: IA-5 (1).1 (v)
#    NIST SP 800-53 Revision 4 :: IA-5 (1) (d)
#
#################################################################
{%- set stig_id = 'RHEL-07-010230' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat2/files' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}
{%- set targFile = '/etc/login.defs' %}
{%- set searchRoot = 'PASS_MIN_DAYS' %}

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
    - repl: '{{ searchRoot }}	1'
  {%- else %}
file_{{ stig_id }}-{{ targFile }}:
  file.append:
    - name: '{{ targFile }}'
    - text: |-
        # Inserted per STIG {{ stig_id }}
        {{ searchRoot }}	1
  {%- endif %}
{%- endif %}
