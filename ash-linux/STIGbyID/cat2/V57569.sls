# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-57569
# Finding ID:	V-57569
# Version:	RHEL-06-000528
# Finding Level:	Medium
#
#     Allowing users to execute binaries from world-writable 
#     directories such as "/tmp" should never be necessary in normal 
#     operation and can expose the system to potential compromise.
#
# CCI: CCI-000381
# NIST SP 800-53 :: CM-7
# NIST SP 800-53A :: CM-7.1 (ii)
# NIST SP 800-53 Revision 4 :: CM-7 a
#
############################################################

script_V57569-describe:
  cmd.script:
  - source: salt://STIGbyID/cat2/files/V57569.sh

# Ingest list of mounted filesystesm into a searchable-structure
{% set mountPoint = '/tmp' %}
{% set activeMntStream = salt['mount.active']('extended=true') %}
{% set mountStruct = activeMntStream[mountPoint] %}

{% if not mountPoint in activeMntStream %}
notify_V57569:
  cmd.run:
  - name: 'echo "''{{ mountPoint }}'' is not on its own partition: nothing to do."'
{% else %}
  # Grab the option-list for mount
  {% set optList = mountStruct['opts'] %}
  # See if the mount has the 'noexec' option set
  {% if 'noexec' in optList %}
notify_V57569-{{ mountPoint }}:
  cmd.run:
  - name: 'echo "''{{ mountPoint }}'' mounted with ''noexec'' option"'
  {% else %}
notify_V57569-{{ mountPoint }}:
  cmd.run:
  - name: 'echo "''{{ mountPoint }}'' not mounted with ''noexec'' option:"'

# Remount with "noexec" option added/set
  {% set optString = 'noexec,' + ','.join(optList) %}
  {% set remountDev = mountStruct['alt_device'] %}
  {% set fsType = mountStruct['fstype'] %}
notify_V57569-{{ mountPoint }}-remount:
  cmd.run:
  - name: 'printf "\t* Attempting remount...\n"'

remount_V57569-{{ mountPoint }}:
  module.run:
  - name: 'mount.remount'
  - m_name: '{{ mountPoint }}'
  - device: '{{ remountDev }}'
  - opts: '{{ optString }}'
  - fstype: '{{ fsType }}'

    # Update fstab (if necessary)
    {% if salt['file.search']('/etc/fstab', '^' + remountDev + '[ 	]') %}
notify_V57569-{{ mountPoint }}-fixFstab:
  cmd.run:
  - name: 'printf "\t* Updating /etc/fstab as necessary\n"'

fstab_V57569-{{ mountPoint }}:
  module.run:
  - name: 'mount.set_fstab'
  - m_name: '{{ mountPoint }}'
  - device: '{{ remountDev }}'
  - opts: '{{ optString }}'
  - fstype: '{{ fsType }}'
    {% endif %}
  {% endif %} 
{% endif %}
