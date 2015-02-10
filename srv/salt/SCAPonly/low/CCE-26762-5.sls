# This Salt test/lockdown implements a SCAP item that has not yet been
# merged into the DISA-published STIGS
#
# Security identifiers:
# - CCE-26762-5
#
# Rule Summary: Set 'nosuid' option on '/tmp' partition
#
# Rule Text: The nosuid mount option can be used to prevent execution of 
#            setuid programs in /tmp. The suid/sgid permissions should 
#            not be required in these world-writable directories. Add 
#            the nosuid option to the fourth column of /etc/fstab for 
#            the line which controls mounting of /tmp.
#
#################################################################

script_CCE-26762-5-describe:
  cmd.script:
  - source: salt://STIGbyID/cat2/files/CCE-26762-5.sh

# Ingest list of mounted filesystesm into a searchable-structure
{% set mountPoint = '/tmp' %}
{% set activeMntStream = salt['mount.active']('extended=true') %}
{% set mountStruct = activeMntStream[mountPoint] %}

{% if not mountPoint in activeMntStream %}
notify_CCE-26762-5:
  cmd.run:
  - name: 'echo "''{{ mountPoint }}'' is not on its own partition: nothing to do."'
{% else %}
  # Grab the option-list for mount
  {% set optList = mountStruct['opts'] %}
  # See if the mount has the 'nosuid' option set
  {% if 'nosuid' in optList %}
notify_CCE-26762-5-{{ mountPoint }}:
  cmd.run:
  - name: 'echo "''{{ mountPoint }}'' mounted with ''nosuid'' option"'
  {% else %}
notify_CCE-26762-5-{{ mountPoint }}:
  cmd.run:
  - name: 'echo "''{{ mountPoint }}'' not mounted with ''nosuid'' option:"'

# Remount with "nosuid" option added/set
  {% set optString = 'nosuid,' + ','.join(optList) %}
  {% set remountDev = mountStruct['alt_device'] %}
  {% set fsType = mountStruct['fstype'] %}
notify_CCE-26762-5-{{ mountPoint }}-remount:
  cmd.run:
  - name: 'printf "\t* Attempting remount...\n"'

remount_CCE-26762-5-{{ mountPoint }}:
  module.run:
  - name: 'mount.remount'
  - m_name: '{{ mountPoint }}'
  - device: '{{ remountDev }}'
  - opts: '{{ optString }}'
  - fstype: '{{ fsType }}'

    # Update fstab (if necessary)
    {% if salt['file.search']('/etc/fstab', '^' + remountDev + '[ 	]') %}
notify_CCE-26762-5-{{ mountPoint }}-fixFstab:
  cmd.run:
  - name: 'printf "\t* Updating /etc/fstab as necessary\n"'

fstab_CCE-26762-5-{{ mountPoint }}:
  module.run:
  - name: 'mount.set_fstab'
  - m_name: '{{ mountPoint }}'
  - device: '{{ remountDev }}'
  - opts: '{{ optString }}'
  - fstype: '{{ fsType }}'
    {% endif %}
  {% endif %} 
{% endif %}
