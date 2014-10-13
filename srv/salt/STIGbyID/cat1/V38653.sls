# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38653
# Finding ID:	V-38653
# Version:	RHEL-06-000341
# Finding Level:	High
#
#     The snmpd service must not use a default password. Presence of the 
#     default SNMP password enables querying of different system aspects 
#     and could result in unauthorized knowledge of the system.
#
############################################################

script_V38653-describe:
  cmd.script:
  - source: salt://STIGbyID/cat1/files/V38653.sh

file_snmpd:
  file.comment:
  - name: /etc/snmp/snmpd.conf
  - regex: ^[a-z].* public
  - char: '## '
  - unless: 'grep -v "^#" /etc/snmp/snmpd.conf | grep public'
