# Finding ID:	RHEL-07-040301
# Version:	RHEL-07-040301_rule
# SRG ID:	SRG-OS-000480-GPOS-00227
# Finding Level:	medium
# 
# Rule Summary:
#	The system must display the date and time of the last
#	successful account logon upon an SSH logon.
#
# CCI-000366 
#    NIST SP 800-53 :: CM-6 b 
#    NIST SP 800-53A :: CM-6.1 (iv) 
#    NIST SP 800-53 Revision 4 :: CM-6 b 
#
#################################################################
{%- set stig_id = 'RHEL-07-040301' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat2/files' %}
{%- set cfgFile = '/etc/ssh/sshd_config' %}
{%- set parmName = 'PrintLastLog' %}
{%- set parmValu = 'yes' %}

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
