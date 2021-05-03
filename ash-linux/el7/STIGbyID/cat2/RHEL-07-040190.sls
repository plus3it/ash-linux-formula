# Finding ID:	RHEL-07-040190
# Version:	RHEL-07-040190_rule
# SRG ID:	SRG-OS-000163-GPOS-00072
# Finding Level:	medium
#
# Rule Summary:
#	All network connections associated with SSH traffic must
#	terminate at the end of the session or after 10 minutes of
#	inactivity, except to fulfill documented and validated mission
#	requirements.
#
# CCI-001133
# CCI-002361
#    NIST SP 800-53 :: SC-10
#    NIST SP 800-53A :: SC-10.1 (ii)
#    NIST SP 800-53 Revision 4 :: SC-10
#    NIST SP 800-53 Revision 4 :: AC-12
#
#################################################################
{%- set stig_id = 'RHEL-07-040190' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat2/files' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}
{%- set svcName = 'sshd' %}
{%- set cfgFile = '/etc/ssh/sshd_config' %}
{%- set parmName = 'ClientAliveInterval' %}
{%- set parmValu = '600' %}

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
file_{{ stig_id }}-{{ cfgFile }}:
  file.replace:
    - name: '{{ cfgFile }}'
    - pattern: '^\s{{ parmName }} .*$'
    - repl: '{{ parmName }} {{ parmValu }}'
    - append_if_not_found: True
    - not_found_content: |-
        # Inserted per STIG {{ stig_id }}
        {{ parmName }} {{ parmValu }}

service_{{ stig_id }}-{{ cfgFile }}:
  service.running:
    - name: '{{ svcName }}'
    - watch:
      - file: file_{{ stig_id }}-{{ cfgFile }}
{%- endif %}
