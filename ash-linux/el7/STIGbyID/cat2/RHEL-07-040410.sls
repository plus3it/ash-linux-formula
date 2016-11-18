# Finding ID:	RHEL-07-040410
# Version:	RHEL-07-040410_rule
# SRG ID:	SRG-OS-000480-GPOS-00227
# Finding Level:	medium
# 
# Rule Summary:
#	The system must ignore to Internet Protocol version 4 (IPv4)
#	Internet Control Message Protocol (ICMP) redirect messages.
#
# CCI-000366 
#    NIST SP 800-53 :: CM-6 b 
#    NIST SP 800-53A :: CM-6.1 (iv) 
#    NIST SP 800-53 Revision 4 :: CM-6 b 
#
#################################################################
{%- set stig_id = 'RHEL-07-040410' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat2/files' %}
{%- set cfgFile = '/etc/sysctl.conf' %}
{%- set parmNames = [
                      'net.ipv4.conf.all.accept_redirects',
                      'net.ipv4.conf.default.accept_redirects'
                     ] %}
{%- set parmValuTarg = '0' %}

script_{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stig_id }}.sh
    - cwd: /root

{%- for parmName in parmNames %}
  {%- set parmValuCurr = salt.cmd.run('sysctl -n ' + parmName) %}
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
{%- endfor %}
