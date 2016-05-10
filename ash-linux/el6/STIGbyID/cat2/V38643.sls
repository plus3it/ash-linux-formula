# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38643
# Finding ID:	V-38643
# Version:	RHEL-06-000282
# Finding Level:	Medium
#
#     There must be no world-writable files on the system. Data in 
#     world-writable files can be modified by any user on the system. 
#     In almost all circumstances, files can be configured using a 
#     combination of user and group permissions to support whatever 
#     legitimate access is needed without the risk caused by 
#     world-writable files. 
#
#  CCI: CCI-000366
#  NIST SP 800-53 :: CM-6 b
#  NIST SP 800-53A :: CM-6.1 (iv)
#  NIST SP 800-53 Revision 4 :: CM-6 b
#
############################################################
{%- set stigId = 'V38643' %}
{%- set helperLoc = 'ash-linux/el6/STIGbyID/cat2/files' %}

script_{{ stigId }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stigId }}.sh
    - cwd: '/root'

# Ingest list of mounted filesystesm into a searchable-structure
{%- set activeMntStream = salt['mount.active']('extended=true') %}

# Iterate the structure by top-level key
{%- for mountPoint in activeMntStream.keys() %}

# Unpack key values out to searchable dictionary
{%- set mountList = activeMntStream[mountPoint] %}

# Pull fstype value from key-value dictionary
{%- set fsType = mountList['fstype'] %}

# Perform action if mount-type is an EXT-type
{%- if fsType == 'ext2' or fsType == 'ext3' or fsType == 'ext4' %}
notify_{{ stigId }}-{{ mountPoint }}:
  cmd.run:
    - name: 'echo "Checking ''{{ mountPoint }}'' for world-writable files"'

strip_{{ stigId }}-{{ mountPoint }}:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stigId }}-helper.sh
    - cwd: '/root'
    - args: {{ mountPoint }}

{%- endif %} 
{%- endfor %}
