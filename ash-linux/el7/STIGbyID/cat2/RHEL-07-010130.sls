# Finding ID:	RHEL-07-010130
# Version:	RHEL-07-010130_rule
# SRG ID:	SRG-OS-000072-GPOS-00040
# Finding Level:	medium
# 
# Rule Summary:
#	When passwords are changed a minimum of eight of the total
#	number of characters must be changed.
#
# CCI-000195 
#    NIST SP 800-53 :: IA-5 (1) (b) 
#    NIST SP 800-53A :: IA-5 (1).1 (v) 
#    NIST SP 800-53 Revision 4 :: IA-5 (1) (b) 
#
#################################################################
{%- set stig_id = 'RHEL-07-010130' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat2/files' %}
{%- set cfgFile = '/etc/security/pwquality.conf' %}
{%- set parmName = 'difok' %}
{%- set parmValu = '8' %}
{%- set parmDesc = 'new' %}

script_{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stig_id }}.sh
    - cwd: /root

{%- if salt.file.search(cfgFile, '^' + parmName) %}
file_{{ stig_id }}-{{ cfgFile }}:
  file.replace:
    - name: '{{ cfgFile }}'
    - pattern: '^{{ parmName }}.*$'
    - repl: '{{ parmName }} = {{ parmValu }}'
{%- else %}
file_{{ stig_id }}-{{ cfgFile }}:
  file.append:
    - name: '{{ cfgFile }}'
    - text: |-
        # Inserted per STIG-ID {{ stig_id }}:
        # * Require new passwords to have at least {{ parmName }} {{ parmDesc }} characters
        {{ parmName }} = {{ parmValu }}
{%- endif %}
