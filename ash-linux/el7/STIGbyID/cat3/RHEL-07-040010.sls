# Finding ID:	RHEL-07-040010
# Version:	RHEL-07-040010_rule
# SRG ID:	SRG-OS-000027-GPOS-00008
# Finding Level:	low
# 
# Rule Summary:
#	The operating system must limit the number of concurrent sessions to 10 for all accounts and/or account types.
#
# CCI-000054 
#    NIST SP 800-53 :: AC-10 
#    NIST SP 800-53A :: AC-10.1 (ii) 
#    NIST SP 800-53 Revision 4 :: AC-10 
#
#################################################################
{%- set stig_id = 'RHEL-07-040010' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat3/files' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}
{%- set cfgFile = '/etc/security/limits.conf' %}
{%- set parmName = 'maxlogins' %}
{%- set parmValu = '10' %}

script_{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stig_id }}.sh
    - cwd: /root

{%- if stig_id in skipIt %}
{%- else %}
file_{{ stig_id }}-{{ cfgFile }}:
  file.replace:
    - name: '{{ cfgFile }}' 
    - pattern: '^\*[ 	]hard[ 	]{{ parmName }}.*$'
    - repl: '*	hard	{{ parmName }}	{{ parmValu }}'
    - append_if_not_found: True
    - not_found_content: |-
        # Inserted per STIG {{ stig_id }}
        *	hard	{{ parmName }}	{{ parmValu }}

{%- endif %}
