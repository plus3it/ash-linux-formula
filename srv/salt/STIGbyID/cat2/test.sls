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

# Ingest list of mounted filesystesm into a searchable-structure
{% set netIfStream = salt['network.interfaces']() %}

# Iterate the top-level dictionary by key
{% for netIfBase in netIfStream.keys() %}
  {% if not netIfBase == 'lo' %}
test_IfPrint-{{ netIfBase }}:
  cmd.run:
  - name: 'echo "Base Interface Name: {{ netIfBase }}"'

  {% set inetList = netIfBase['inet'] %}

  {% endif %}
{% endfor %}


#######################################################################
# Investigate use of "network.interfaces" Salt-module:
# data = {'local': {'lo': {'hwaddr': '00:00:00:00:00:00', 'up': True, 'inet': [{'broadcast': None, 'netmask': '255.0.0.0', 'label': 'lo', 'address': '127.0.0.1'}]}, 'eth0': {'hwaddr': '0a:db:89:de:10:94', 'up': True, 'inet': [{'broadcast': '172.31.15.255', 'netmask': '255.255.240.0', 'label': 'eth0', 'address': '172.31.2.104'}, {'broadcast': '192.168.22.255', 'netmask': '255.255.255.0', 'label': 'eth0:100', 'address': '192.168.22.100'}]}}}
# Top
#  (Dictionary)
#     Key: <interface-names>
#     Val: Dictionary
#       Key: "inet"
#       Val: <list>
#         Dictionaries
#           Key: "label"
#           Val: <interface-label>
# local:
#     ----------
#     eth0:
#         ----------
#         hwaddr:
#             0a:db:89:de:10:94
#         inet:
#             |_
#               ----------
#               address:
#                   172.31.2.104
#               broadcast:
#                   172.31.15.255
#               label:
#                   eth0
#               netmask:
#                   255.255.240.0
#             |_
#               ----------
#               address:
#                   192.168.22.100
#               broadcast:
#                   192.168.22.255
#               label:
#                   eth0:100
#               netmask:
#                   255.255.255.0
#         up:
#             True
# 
# Grab the if->inet->label value, then look in 
# /etc/sysconfig/network-scripts for config files using DHCP on active 
# interfaces?
#######################################################################
