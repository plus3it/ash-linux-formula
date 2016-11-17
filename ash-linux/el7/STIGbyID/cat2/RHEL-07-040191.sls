# Finding ID:	RHEL-07-040191
# Version:	RHEL-07-040191_rule
# SRG ID:	SRG-OS-000163-GPOS-00072
# Finding Level:	medium
# 
# Rule Summary:
#	All network connections associated with SSH traffic must
#	terminate after a period of inactivity.
#
# CCI-001133 
# CCI-002361 
#    NIST SP 800-53 :: SC-10 
#    NIST SP 800-53A :: SC-10.1 (ii) 
#    NIST SP 800-53 Revision 4 :: SC-10 
#    NIST SP 800-53 Revision 4 :: AC-12 
#
#################################################################
{%- set stig_id = 'RHEL-07-040191' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat2/files' %}
{%- set cfgFile = '/etc/ssh/sshd_config' %}
{%- set parmName = 'ClientAliveCountMax' %}
{%- set parmValu = '0' %}

script_{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stig_id }}.sh
    - cwd: /root

file_{{ stig_id }}-{{ cfgFile }}:
  file.replace:
    - name: '{{ cfgFile }}'
    - pattern: '^\s{{ parmName }} .*$'
    - repl: '{{ parmName }} {{ parmValu }}'
    - append_if_not_found: True
    - not_found_content: |
        # Inserted per STIG {{ stig_id }}
        {{ parmName }} {{ parmValu }}

service_{{ stig_id }}-{{ cfgFile }}:
  service.running:
    - name: sshd
    - watch:
      - file: file_{{ stig_id }}-{{ cfgFile }}
