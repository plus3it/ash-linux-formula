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
{%- set stigId = 'V38679' %}
{%- set helperLoc = 'ash-linux/el6/STIGbyID/cat2/files' %}

script_{{ stigId }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stigId }}.sh
    - cwd: '/root'

{%- set netCfgRoot = '/etc/sysconfig/network-scripts/ifcfg-' %}

#####################################################################
# The following logic is probably overly-exhaustive in identifying
# interfaces that might be using DHCP. However, it should handle
# Hosts that use IP aliasing, interface-bonding and/or tagged VLANs
#####################################################################

# Ingest list of mounted filesystesm into a searchable-structure
{%- set netIfStream = salt['network.interfaces']() %}

# Start digging down into the structure to get our network-labels
{%- for netIfBase in netIfStream.keys() %}
  {%- if not netIfBase == 'lo' %}
    {%- set inetList = netIfBase['inet'] %}
    {%- set ifDict = netIfStream[netIfBase] %}
    {%- set ifInetList = ifDict['inet'] %}

    # Iterate our list of labels
    {%- for listElem in ifInetList %}
      {%- set ifLabel = listElem['label'] %}
      # Check if there's a "network-scripts" config file
      {%- if salt.file.file_exists(netCfgRoot + ifLabel) %}
notify_{{ stigId }}-{{ ifLabel }}:
  cmd.run:
    - name: 'echo "Checking {{ netCfgRoot }}{{ ifLabel }} for DCHP use."'
        # Check if boot-time interface configuration uses DHCP and alert
        {%- if salt.file.search(netCfgRoot + ifLabel, 'dhcp') %}
notify_{{ stigId }}-{{ ifLabel }}_DHCP:
  cmd.run:
    - name: 'echo "WARNING: Interface ''{{ ifLabel }}'' configured for DHCP"'
        {%- else %}
notify_{{ stigId }}-{{ ifLabel }}_DHCP:
  cmd.run:
    - name: 'echo "Info: Interface ''{{ ifLabel }}'' does not use DHCP"'
        {%- endif %}
      {%- endif %}
    {%- endfor %}

  {%- endif %}
{%- endfor %}
