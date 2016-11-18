# Finding ID:	RHEL-07-040470
# Version:	RHEL-07-040470_rule
# SRG ID:	SRG-OS-000480-GPOS-00227
# Finding Level:	medium
# 
# Rule Summary:
#	Network interfaces must not be in promiscuous mode.
#
# CCI-000366 
#    NIST SP 800-53 :: CM-6 b 
#    NIST SP 800-53A :: CM-6.1 (iv) 
#    NIST SP 800-53 Revision 4 :: CM-6 b 
#
#################################################################
{%- set stig_id = 'RHEL-07-040470' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat2/files' %}
{%- set ifList = salt.network.interfaces().keys() %}
{%- set ifMode = 'PROMISC' %}
{%- set modeTarg = 'off' %}

script_{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stig_id }}.sh
    - cwd: /root

{%- for if in ifList %}
  {%- if salt.cmd.run('ip link show ' + if + ' | grep ' + ifMode) %}
property_{{ stig_id }}-{{ if }}:
  cmd.run:
    - name: 'printf "Turning off promiscuous mode on {{ if }} " && ip link set {{ if }} promisc {{ modeTarg }} && echo "...SUCCESS" || echo "...FAILED"'
    - cwd: /root
  {%- else %}
property_{{ stig_id }}-{{ if }}:
  cmd.run:
    - name: 'echo "Interface {{ if }} (already) not in promicuous mode."'
    - cwd: /root
  {%- endif %}
{%- endfor %}
