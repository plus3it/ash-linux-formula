# Finding ID:	RHEL-07-040421
# Version:	RHEL-07-040421_rule
# SRG ID:	SRG-OS-000480-GPOS-00227
# Finding Level:	medium
# 
# Rule Summary:
#	The system must not send Internet Protocol version 4 (IPv4)
#	Internet Control Message Protocol (ICMP) redirects.
#
# CCI-000366 
#    NIST SP 800-53 :: CM-6 b 
#    NIST SP 800-53A :: CM-6.1 (iv) 
#    NIST SP 800-53 Revision 4 :: CM-6 b 
#
#################################################################
{%- set stig_id = 'RHEL-07-040421' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat2/files' %}
{%- set cfgFile = '/etc/sysctl.conf' %}
{%- set parmName = 'net.ipv4.conf.all.send_redirects' %}
{%- set parmValuCurr = salt['cmd.shell']('sysctl -n ' + parmName) %}
{%- set parmValuTarg = '0' %}

script_{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stig_id }}.sh
    - cwd: /root

sysctl_{{ stig_id }}-{{ parmName }}:
  sysctl.present:
    - name: '{{ parmName }}'
    - value: '{{ parmValuTarg }}'

file_{{ stig_id }}-{{ parmName }}:
  file.replace:
    - name: '{{ cfgFile }}'
    - pattern: '^{{ parmName }} = .*$'
    - repl: '{{ parmName }} = {{ parmValuTarg }}'
    - append_if_not_found: True
    - not_found_content: |-
        # Inserted per STIG {{ stig_id }}
        #         {{ parmName }} = {{ parmValuTarg }}
