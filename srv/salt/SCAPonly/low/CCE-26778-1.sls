# This Salt test/lockdown implements a SCAP item that has not yet been
# merged into the DISA-published STIGS
#
# Security identifiers:
# - CCE-26778-1
#
# Rule Summary: Set 'nodev' option on '/dev/shm' partition
#
# Rule Text: The nodev mount option can be used to prevent creation of 
#            device files in /dev/shm. Legitimate character and block 
#            devices should not exist within temporary directories like 
#            /dev/shm. Add the nodev option to the fourth column of 
#            /etc/fstab for the line which controls mounting of /dev/shm.
#
#################################################################

script_CCE-26778-1-describe:
  cmd.script:
  - source: salt://SCAPonly/low/files/CCE-26778-1.sh

# Ingest list of mounted filesystesm into a searchable-structure
{% set mountPoint = '/dev/shm' %}
{% set activeMntStream = salt['mount.active']('extended=true') %}
{% set mountStruct = activeMntStream[mountPoint] %}

{% if not mountPoint in activeMntStream %}
notify_CCE-26778-1:
  cmd.run:
  - name: 'echo "''{{ mountPoint }}'' is not on its own partition: nothing to do."'
{% else %}
  # Grab the option-list for mount
  {% set optList = mountStruct['opts'] %}
  # See if the mount has the 'nodev' option set
  {% if 'nodev' in optList %}
notify_CCE-26778-1-{{ mountPoint }}:
  cmd.run:
  - name: 'echo "''{{ mountPoint }}'' mounted with ''nodev'' option"'
  {% else %}
notify_CCE-26778-1-{{ mountPoint }}:
  cmd.run:
  - name: 'echo "''{{ mountPoint }}'' not mounted with ''nodev'' option:"'

# Remount with "nodev" option added/set
  {% set optString = 'nodev,' + ','.join(optList) %}
  {% set remountDev = mountPoint %}
  {% set fsType = mountStruct['fstype'] %}
notify_CCE-26778-1-{{ mountPoint }}-remount:
  cmd.run:
  - name: 'printf "\t* Attempting remount...\n"'

remount_CCE-26778-1-{{ mountPoint }}:
  module.run:
  - name: 'mount.remount'
  - m_name: '{{ mountPoint }}'
  - device: '{{ remountDev }}'
  - opts: '{{ optString }}'
  - fstype: '{{ fsType }}'

    # Update fstab (if necessary)
    {% if salt['file.search']('/etc/fstab', '^' + remountDev + '[ 	]') %}
notify_CCE-26778-1-{{ mountPoint }}-fixFstab:
  cmd.run:
  - name: 'printf "\t* Updating /etc/fstab as necessary\n"'

fstab_CCE-26778-1-{{ mountPoint }}:
  module.run:
  - name: 'mount.set_fstab'
  - m_name: '{{ mountPoint }}'
  - device: '{{ remountDev }}'
  - opts: '{{ optString }}'
  - fstype: '{{ fsType }}'
    {% endif %}
  {% endif %} 
{% endif %}
