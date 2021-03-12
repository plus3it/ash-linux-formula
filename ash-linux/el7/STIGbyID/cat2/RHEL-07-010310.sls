# STIG ID:	RHEL-07-010310
# Rule ID:	SV-86565r2_rule
# Vuln ID:	V-71941
# SRG ID:	SRG-OS-000118-GPOS-00060
# Finding Level:	medium
#
# Rule Summary:
#	The operating system must disable account identifiers
#	(individuals, groups, roles, and devices) if the password
#	expires.
#
# CCI-000795
#    NIST SP 800-53 :: IA-4 e
#    NIST SP 800-53A :: IA-4.1 (iii)
#    NIST SP 800-53 Revision 4 :: IA-4 e
#
#################################################################
{%- set stig_id = 'RHEL-07-010310' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat2/files' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}
{%- set cfgFile = '/etc/default/useradd' %}
{%- set parmName = 'INACTIVE' %}
{%- set parmValu = '0' %}

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
  {%- if salt.file.search(cfgFile, '^' + parmName) %}
file_{{ stig_id }}-{{ cfgFile }}:
  file.replace:
    - name: '{{ cfgFile }}'
    - pattern: '^{{ parmName }}.*$'
    - repl: '{{ parmName }}={{ parmValu }}'
  {%- else %}
file_{{ stig_id }}-{{ cfgFile }}:
  file.append:
    - name: '{{ cfgFile }}'
    - text: |-
        # Inserted per STIG-ID {{ stig_id }}:
        # * Disable accounts {{ parmValu }} days after they expire
        {{ parmName }}={{ parmValu }}
  {%- endif %}
{%- endif %}
