# Finding ID:	RHEL-07-020200
# Version:	RHEL-07-020200_rule
# SRG ID:	SRG-OS-000437-GPOS-00194
# Finding Level:	low
# 
# Rule Summary:
#	The operating system must remove all software components
#	after updated versions have been installed.
#
# CCI-002617 
#    NIST SP 800-53 Revision 4 :: SI-2 (6) 
#
#################################################################
{%- set stig_id = 'RHEL-07-020200' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat3/files' %}
{%- set cfgFile = '/etc/yum.conf'%}
{%- set parmName = 'clean_requirements_on_remove' %}
{%- set parmValu = '1' %}

script_{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stig_id }}.sh
    - cwd: /root

file_{{ stig_id }}-{{ cfgFile }}:
  file.replace:
    - name: '{{ cfgFile }}'
    - pattern: '^\s{{ parmName }}=.*$'
    - repl: '{{ parmName }}={{ parmValu }}'
    - append_if_not_found: True
    - not_found_content: |-
        # Inserted per STIG {{ stig_id }}
        {{ parmName }}={{ parmValu }}

