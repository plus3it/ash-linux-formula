# Finding ID:	RHEL-07-040400
# Vuln-ID:      V-72253
# Rue ID:       SV-86877r3_rule (sshd_use_approved_macs)
# SRG ID:	SRG-OS-000250-GPOS-00093
# Finding Level:	medium
#
# Rule Summary:
#	The SSH daemon must be configured to only use Message
#	Authentication Codes (MACs) employing FIPS 140-2 approved
#	cryptographic hash algorithms.
#
# CCI-001453
#    NIST SP 800-53 :: AC-17 (2)
#    NIST SP 800-53A :: AC-17 (2).1
#    NIST SP 800-53 Revision 4 :: AC-17 (2)
#
#################################################################
{%- set stig_id = 'RHEL-07-040400' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat2/files' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}
{%- set svcName = 'sshd' %}
{%- set cfgFile = '/etc/ssh/sshd_config' %}
{%- set parmName = 'MACs' %}
{%- set parmValu = 'hmac-sha2-512,hmac-sha2-256' %}

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
    - pattern: '^\s*{{ parmName }} .*$'
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
