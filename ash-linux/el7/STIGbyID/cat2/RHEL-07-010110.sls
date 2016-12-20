# Finding ID:	RHEL-07-010110
# Version:	RHEL-07-010110_rule
# SRG ID:	SRG-OS-000071-GPOS-00039
# Finding Level:	medium
# 
# Rule Summary:
#	When passwords are changed or new passwords are assigned, the
#	new password must contain at least one numeric character.
#
# CCI-000194 
#    NIST SP 800-53 :: IA-5 (1) (a) 
#    NIST SP 800-53A :: IA-5 (1).1 (v) 
#    NIST SP 800-53 Revision 4 :: IA-5 (1) (a) 
#
#################################################################
{%- set stig_id = 'RHEL-07-010110' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat2/files' %}
{%- set cfgFile = '/etc/security/pwquality.conf' %}
{%- set parmName = 'dcredit' %}
{%- set parmValu = '-1' %}
{%- set parmDesc = 'numeric' %}

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
        # * Require new passwords to have at least one {{ parmDesc }} character
        {{ parmName }} = {{ parmValu }}
{%- endif %}
