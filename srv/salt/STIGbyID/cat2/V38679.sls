# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38679
# Finding ID:	V-38679
# Version:	RHEL-06-000292
# Finding Level:	Medium
#
#     The DHCP client must be disabled if not needed. DHCP relies on 
#     trusting the local network. If the local network is not trusted, then 
#     it should not be used. However, the automatic configuration provided 
#     by DHCP is commonly used and the alternative, ...
#
#  CCI: CCI-000366
#  NIST SP 800-53 :: CM-6 b
#  NIST SP 800-53A :: CM-6.1 (iv)
#  NIST SP 800-53 Revision 4 :: CM-6 b
#
############################################################

script_V38679-describe:
  cmd.script:
  - source: salt://STIGbyID/cat2/files/V38679.sh

cmd_V38679-NotImplemented:
  cmd.run:
  - name: 'echo "NOT YET IMPLEMENTED"'

{% set netCfgRoot = '/etc/sysconfig/network-scripts/ifcfg-' %}

{% set netIfs = salt['grains.item']('ip4_interfaces') %}
{% for ipv4If in netIfs['ip4_interfaces'] %}
{% if not ipv4If == 'lo' %}
notify_V38679-{{ ipv4If }}:
  cmd.run:
  - name: 'echo "Checking if interface ''{{ ipv4If }}'' is configured for DHCP"'
{% endif %}
{% endfor %}
