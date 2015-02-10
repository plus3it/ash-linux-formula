# This Salt test/lockdown implements a SCAP item that has not yet been
# merged into the DISA-published STIGS
#
# Security identifiers:
# - CCE-26499-4
#
# Rule Summary: Set 'nodev' option on '/tmp' partition
#
# Rule Text: The nodev mount option can be used to prevent device files 
#            from being created in /tmp. Legitimate character and block 
#            devices should not exist within temporary directories like 
#            /tmp. Add the nodev option to the fourth column of 
#            /etc/fstab for the line which controls mounting of /tmp.
#
#################################################################

script_CCE-26499-4-describe:
  cmd.script:
  - source: salt://SCAPonly/low/files/CCE-26499-4.sh
  - cwd: '/root'

# Ingest list of mounted filesystesm into a searchable-structure
{% set mountPoint = '/tmp' %}
{% set activeMntStream = salt['mount.active']('extended=true') %}
{% set mountStruct = activeMntStream[mountPoint] %}

{% if not mountPoint in activeMntStream %}
notify_CCE-26499-4:
  cmd.run:
  - name: 'echo "''{{ mountPoint }}'' is not on its own partition: nothing to do."'
{% else %}
  # Grab the option-list for mount
  {% set optList = mountStruct['opts'] %}
  # See if the mount has the 'nodev' option set
  {% if 'nodev' in optList %}
notify_CCE-26499-4-{{ mountPoint }}:
  cmd.run:
  - name: 'echo "''{{ mountPoint }}'' mounted with ''nodev'' option"'
  {% else %}
notify_CCE-26499-4-{{ mountPoint }}:
  cmd.run:
  - name: 'echo "''{{ mountPoint }}'' not mounted with ''nodev'' option:"'

# Remount with "nodev" option added/set
  {% set optString = 'nodev,' + ','.join(optList) %}
  {% set remountDev = mountStruct['alt_device'] %}
  {% set fsType = mountStruct['fstype'] %}
notify_CCE-26499-4-{{ mountPoint }}-remount:
  cmd.run:
  - name: 'printf "\t* Attempting remount...\n"'

remount_CCE-26499-4-{{ mountPoint }}:
  module.run:
  - name: 'mount.remount'
  - m_name: '{{ mountPoint }}'
  - device: '{{ remountDev }}'
  - opts: '{{ optString }}'
  - fstype: '{{ fsType }}'

    # Update fstab (if necessary)
    {% if salt['file.search']('/etc/fstab', '^' + remountDev + '[ 	]') %}
notify_CCE-26499-4-{{ mountPoint }}-fixFstab:
  cmd.run:
  - name: 'printf "\t* Updating /etc/fstab as necessary\n"'

fstab_CCE-26499-4-{{ mountPoint }}:
  module.run:
  - name: 'mount.set_fstab'
  - m_name: '{{ mountPoint }}'
  - device: '{{ remountDev }}'
  - opts: '{{ optString }}'
  - fstype: '{{ fsType }}'
    {% endif %}
  {% endif %} 
{% endif %}
