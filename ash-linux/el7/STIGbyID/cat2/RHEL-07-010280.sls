# STIG ID:	RHEL-07-010280
# Rule ID:	SV-86559r2_rule
# Vuln ID:	V-71935
# SRG ID:	SRG-OS-000078-GPOS-00046
# Finding Level:	medium
#
# Rule Summary:
#	Passwords must be a minimum of 15 characters in length.
#
# CCI-000205
#    NIST SP 800-53 :: IA-5 (1) (a)
#    NIST SP 800-53A :: IA-5 (1).1 (i)
#    NIST SP 800-53 Revision 4 :: IA-5 (1) (a)
#
#################################################################
{%- set stig_id = 'RHEL-07-010280' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat2/files' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}
{%- set cfgFile = '/etc/security/pwquality.conf' %}
{%- set parmName = 'minlen' %}
{%- set parmValu = '15' %}
{%- set parmDesc = 'in length' %}

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
        # * Prohibit setting passwords shorter than {{ parmValu }} {{ parmDesc }}
        {{ parmName }} = {{ parmValu }}
  {%- endif %}
{%- endif %}
