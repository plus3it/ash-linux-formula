# Finding ID:	RHEL-07-040350
# Version:	RHEL-07-040350_rule
# SRG ID:	SRG-OS-000480-GPOS-00227
# Finding Level:	medium
# 
# Rule Summary:
#	The system must not forward Internet Protocol version 4 (IPv4)
#	source-routed packets.
#
# CCI-000366 
#    NIST SP 800-53 :: CM-6 b 
#    NIST SP 800-53A :: CM-6.1 (iv) 
#    NIST SP 800-53 Revision 4 :: CM-6 b 
#
#################################################################
{%- set stig_id = 'RHEL-07-040350' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat2/files' %}
{%- set cfgFile = '/etc/sysctl.conf' %}
{%- set parmName = 'net.ipv4.conf.all.accept_source_route' %}
{%- set parmValuCurr = salt.cmd.run('sysctl -n ' + parmName) %}
{%- set parmValuTarg = '0' %}

script_{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stig_id }}.sh
    - cwd: /root

{%- if parmValuCurr == '0' %}
cmd_{{ stig_id }}-{{ parmName }}:
  cmd.run:
    - name: 'echo "{{ parmName }} already set to {{ parmValuTarg }}"'
    - cwd: /root
{%- else %}
cmd_{{ stig_id }}-{{ parmName }}:
  cmd.run:
    - name: 'sysctl -w {{ parmName }}={{ parmValuTarg }} '
    - cwd: /root
file_{{ stig_id }}-{{ parmName }}:
  file.replace:
    - name: '{{ cfgFile }}'
    - pattern: '^{{ parmName }} = .*$'
    - repl: '{{ parmName }} = {{ parmValuTarg }}'
    - append_if_not_found: True
    - not_found_content: |
        # Inserted per STIG {{ stig_id }}
        {{ parmName }} = {{ parmValuTarg }}
{%- endif %}
