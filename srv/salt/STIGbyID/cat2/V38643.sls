# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38643
# Finding ID:	V-38643
# Version:	RHEL-06-000282
# Finding Level:	Medium
#
#     There must be no world-writable files on the system. Data in 
#     world-writable files can be modified by any user on the system. In 
#     almost all circumstances, files can be configured using a combination 
#     of user and group permissions to support whatever ...
#
############################################################

script_V38643-describe:
  cmd.script:
  - source: salt://STIGbyID/cat2/files/V38643.sh

# Ingest list of mounted filesystesm into a searchable-structure
{% set activeMntStream = salt['mount.active']('extended=true') %}

# Iterate the structure by top-level key
{% for mountPoint in activeMntStream.keys() %}

# Unpack key values out to searchable dictionary
{% set mountList = activeMntStream[mountPoint] %}

# Pull fstype value from key-value dictionary
{% set fsType = mountList['fstype'] %}

# Perform action if mount-type is an EXT-type
{% if fsType == 'ext2' or fsType == 'ext3' or fsType == 'ext4' %}
notify_V38643-{{ mountPoint }}:
  cmd.run:
  - name: 'echo "Checking ''{{ mountPoint }}'' for world-writable files"'

strip_V38643-{{ mountPoint }}:
  cmd.script:
  - source: salt://STIGbyID/cat2/files/V38643-helper.sh
  - args: {{ mountPoint }}

{% endif %} 
{% endfor %}
