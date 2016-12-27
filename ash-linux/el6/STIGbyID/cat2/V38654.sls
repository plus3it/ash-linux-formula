# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38654
# Finding ID:	V-38654
# Version:	RHEL-06-000270
# Finding Level:	Medium
#
#     Remote file systems must be mounted with the nosuid option. NFS 
#     mounts should not present suid binaries to users. Only 
#     vendor-supplied suid executables should be installed to their default 
#     location on the local filesystem.
#
#  CCI: CCI-000366
#  NIST SP 800-53 :: CM-6 b
#  NIST SP 800-53A :: CM-6.1 (iv)
#  NIST SP 800-53 Revision 4 :: CM-6 b
#
############################################################
{%- set stigId = 'V38654' %}
{%- set helperLoc = 'ash-linux/el6/STIGbyID/cat2/files' %}

script_V38654-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/V38654.sh
    - cwd: '/root'

# Ingest list of mounted filesystesm into a searchable-structure
{%- set activeMntStream = salt['mount.active']('extended=true') %}

# Iterate the structure by top-level key
{%- for mountPoint in activeMntStream.keys() %}

# Unpack key values out to searchable dictionary
{%- set mountList = activeMntStream[mountPoint] %}

# Pull fstype value from key-value dictionary
{%- set fsType = mountList['fstype'] %}

# Perform action if mount-type is an NFS-type
{%- if fsType == 'nfs' or fsType == 'nfs4' %}

# Grab the option-list for mount
{%- set optList = mountList['opts'] %}
  # See if the mount has the 'nosuid' option set
  {%- if 'nosuid' in optList %}
notify_V38654-{{ mountPoint }}:
  cmd.run:
    - name: 'echo "NFS mount {{ mountPoint }} mounted with ''nosuid'' option"'
  {%- else %}
notify_V38654-{{ mountPoint }}:
  cmd.run:
    - name: 'echo "NFS mount {{ mountPoint }} not mounted with ''nosuid'' option:"'

# Remount with "nosuid" option added/set
  {%- set optString = 'nosuid,' + ','.join(optList) %}
  {%- set remountDev = mountList['alt_device'] %}
notify_V38654-{{ mountPoint }}-remount:
  cmd.run:
    - name: 'printf "\t* Attempting remount... {{ remountDev }}\n"'

remount_V38654-{{ mountPoint }}:
  module.run:
    - name: 'mount.remount'
    - m_name: '{{ mountPoint }}'
    - device: '{{ remountDev }}'
    - fstype: '{{ fsType }}'
    - opts: '{{ optString }}'

    # Update fstab (if necessary)
    {%- if salt.file.search('/etc/fstab', '^' + remountDev + '[ 	]') %}
notify_V38654-{{ mountPoint }}-fixFstab:
  cmd.run:
    - name: 'printf "\t* Updating /etc/fstab as necessary\n"'

fstab_V38654-{{ mountPoint }}:
  module.run:
    - name: 'mount.set_fstab'
    - m_name: '{{ mountPoint }}'
    - device: '{{ remountDev }}'
    - fstype: '{{ fsType }}'
    - opts: '{{ optString }}'
    {%- endif %}

  {%- endif %}
{%- endif %} 
{%- endfor %}
