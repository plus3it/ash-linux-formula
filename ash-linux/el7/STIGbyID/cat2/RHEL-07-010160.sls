# STIG ID:	RHEL-07-010160
# Rule ID:	SV-86535r2_rule
# Vuln ID:	V-71911
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
{%- set stig_id = 'RHEL-07-010160' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat2/files' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}
{%- set cfgFile = '/etc/security/pwquality.conf' %}
{%- set parmName = 'difok' %}
{%- set parmValu = '8' %}
{%- set parmDesc = 'new' %}

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
        # * Require new passwords to have at least {{ parmName }} {{ parmDesc }} characters
        {{ parmName }} = {{ parmValu }}
  {%- endif %}
{%- endif %}
