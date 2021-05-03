# STIG ID:	RHEL-07-040110
# Rule ID:	SV-86845r3_rule
# Vuln ID:	V-72221
# SRG ID:	SRG-OS-000033-GPOS-00014
# Finding Level:	medium
#
# Rule Summary:
#	A FIPS 140-2 approved cryptographic algorithm must be used for
#	SSH communications.
#
# CCI-000068
# CCI-000366
# CCI-000803
#    NIST SP 800-53 :: AC-17 (2)
#    NIST SP 800-53A :: AC-17 (2).1
#    NIST SP 800-53 Revision 4 :: AC-17 (2)
#    NIST SP 800-53 :: CM-6 b
#    NIST SP 800-53A :: CM-6.1 (iv)
#    NIST SP 800-53 Revision 4 :: CM-6 b
#    NIST SP 800-53 :: IA-7
#    NIST SP 800-53A :: IA-7.1
#    NIST SP 800-53 Revision 4 :: IA-7
#
#################################################################
{%- set stig_id = 'RHEL-07-040110' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat2/files' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}
{%- set svcName = 'sshd' %}
{%- set cfgFile = '/etc/ssh/sshd_config' %}
{%- set parmName = 'Ciphers' %}
{%- set parmValu = 'aes128-ctr,aes192-ctr,aes256-ctr' %}

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
    - pattern: '^\s*{{ parmName }}.*$'
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
