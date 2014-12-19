# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38652
# Finding ID:	V-38652
# Version:	RHEL-06-000269
# Finding Level:	Medium
#
#     Remote file systems must be mounted with the nodev option. Legitimate 
#     device files should only exist in the /dev directory. NFS mounts 
#     should not present device files to users.
#
#  CCI: CCI-000366
#  NIST SP 800-53 :: CM-6 b
#  NIST SP 800-53A :: CM-6.1 (iv)
#  NIST SP 800-53 Revision 4 :: CM-6 b
#
############################################################

script_V38652-describe:
  cmd.script:
  - source: salt://STIGbyID/cat2/files/V38652.sh

# Ingest list of mounted filesystesm into a searchable-structure
{% set activeMntStream = salt['mount.active']('extended=true') %}

# Iterate the structure by top-level key
{% for mountPoint in activeMntStream.keys() %}

# Unpack key's value out to searchable dictionary
{% set mountList = activeMntStream[mountPoint] %}

# Pull fstype value from key's dictionary
{% set fsType = mountList['fstype'] %}

# Perform action if mount-type is an NFS-type
{% if fsType == 'nfs' or fsType == 'nfs4' %}

# Grab the mount's option-list
{% set optList = mountList['opts'] %}
  # See if the mount has the 'nodev' option set
  {% if 'nodev' in optList %}
notify_V38652-{{ mountPoint }}:
  cmd.run:
  - name: 'echo "NFS mount {{ mountPoint }} mounted with ''nodev'' option"'
  {% else %}
notify_V38652-{{ mountPoint }}:
  cmd.run:
  - name: 'echo "NFS mount {{ mountPoint }} not mounted with ''nodev'' option. Remounting..."'

# Remount with 'nodev' option added/set
  {% set optString = ','.join(optList) + ',nodev' %}
  {% set remountDev = mountList['device'] %}
remount_V38652-{{ mountPoint }}:
  cmd.run:
  - name: 'mount -o remount,{{ optString }} {{ mountPoint }}'

  {% endif %}
{% endif %} 
{% endfor %}
