# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38660
# Finding ID:	V-38660
# Version:	RHEL-06-000340
# Finding Level:	Medium
#
#     The snmpd service must use only SNMP protocol version 3 or newer. 
#     Earlier versions of SNMP are considered insecure, as they potentially 
#     allow unauthorized access to detailed system management information.
#
#  CCI: CCI-000366
#  NIST SP 800-53 :: CM-6 b
#  NIST SP 800-53A :: CM-6.1 (iv)
#  NIST SP 800-53 Revision 4 :: CM-6 b
#
############################################################

{%- set stigId = 'V38660' %}
{%- set helperLoc = 'ash-linux/el6/STIGbyID/cat2/files' %}
{%- set snmpConf = '/etc/snmp/snmpd.conf' %}

script_{{ stigId }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stigId }}.sh
    - cwd: '/root'

{%- if not salt.pkg.version('net-snmp') %}
cmd_{{ stigId }}-notice:
  cmd.run:
    - name: 'echo "Info: SNMP packages not installed - nothing to address"'
{%- elif salt.file.search(snmpConf, '^[a-z].*(?:v1|v2c|om2sec)') %}
file_{{ stigId }}-commentV1n2s:
  file.comment:
    - name: '{{ snmpConf }}'
    - regex: '^[a-z].*(v1|v2c|om2sec)'
{%- endif %}

