# Finding ID:	RHEL-07-040580
# Version:	RHEL-07-040580_rule
# SRG ID:	SRG-OS-000480-GPOS-00227
# Finding Level:	high
# 
# Rule Summary:
#	SNMP community strings must be changed from the default.
#
# CCI-000366 
#    NIST SP 800-53 :: CM-6 b 
#    NIST SP 800-53A :: CM-6.1 (iv) 
#    NIST SP 800-53 Revision 4 :: CM-6 b 
#
#################################################################
{%- set stig_id = 'RHEL-07-040580' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat1/files' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}
{%- set snmpCfg = '/etc/snmp/snmpd.conf' %}
{%- set forbidStrs = [
                      'public',
                      'private'
                     ] %}

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
{%- elif (
        salt.pkg.version('net-snmp') or
        salt.file.file_exists(snmpCfg)
       ) %}
  {%- for community in forbidStrs %}
    {%- if salt.file.search(snmpCfg, community) %}
file_{{ stig_id }}-{{ community }}:
  file.comment:
    - name: '{{ snmpCfg }}'
    - regex: '^[A-Za-z].*\s{{ community }}'
    - char: '#'
    {%- endif %}
  {%- endfor %}
{%- else %}
cmd_{{ stig_id }}-missing:
  cmd.run:
    - name: 'printf "\nchanged=no comment=''No SNMP agent installed''\n"'
    - cwd: /root
    - stateful: True
{%- endif %}
