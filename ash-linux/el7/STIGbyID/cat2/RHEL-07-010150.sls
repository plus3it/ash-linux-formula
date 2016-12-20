# Finding ID:	RHEL-07-010150
# Version:	RHEL-07-010150_rule
# SRG ID:	SRG-OS-000072-GPOS-00040
# Finding Level:	medium
# 
# Rule Summary:
#	When passwords are changed the number of repeating consecutive
#	characters must not be more than four characters.
#
# CCI-000195 
#    NIST SP 800-53 :: IA-5 (1) (b) 
#    NIST SP 800-53A :: IA-5 (1).1 (v) 
#    NIST SP 800-53 Revision 4 :: IA-5 (1) (b) 
#
#################################################################
{%- set stig_id = 'RHEL-07-010150' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat2/files' %}
{%- set cfgFile = '/etc/security/pwquality.conf' %}
{%- set parmName = 'maxrepeat' %}
{%- set parmValu = '2' %}
{%- set parmDesc = 'repeating' %}

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
        # * Prohibit new passwords from including more than {{ parmValu }} {{ parmDesc }} characters
        {{ parmName }} = {{ parmValu }}
{%- endif %}
