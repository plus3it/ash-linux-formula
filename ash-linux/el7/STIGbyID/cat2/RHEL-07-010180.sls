# STIG ID:	RHEL-07-010180
# Rule ID:	SV-86539r3_rule
# Vuln ID:	V-71915
# SRG ID:	SRG-OS-000072-GPOS-00040
# Finding Level:	medium
#
# Rule Summary:
#	When passwords are changed the number of repeating consecutive
#	characters must not be more than three characters.
#
# CCI-000195
#    NIST SP 800-53 :: IA-5 (1) (b)
#    NIST SP 800-53A :: IA-5 (1).1 (v)
#    NIST SP 800-53 Revision 4 :: IA-5 (1) (b)
#
#################################################################
{%- set stig_id = 'RHEL-07-010180' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat2/files' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}
{%- set cfgFile = '/etc/security/pwquality.conf' %}
{%- set parmName = 'maxrepeat' %}
{%- set parmValu = '3' %}
{%- set parmDesc = 'repeating' %}

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
{%- endif %}
