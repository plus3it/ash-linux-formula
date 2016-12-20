# Finding ID:	RHEL-07-010280
# Version:	RHEL-07-010280_rule
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
{%- set stig_id = 'RHEL-07-010280' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat2/files' %}
{%- set cfgFile = '/etc/default/useradd' %}
{%- set parmName = 'INACTIVE' %}
{%- set parmValu = '0' %}

script_{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stig_id }}.sh
    - cwd: /root

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
