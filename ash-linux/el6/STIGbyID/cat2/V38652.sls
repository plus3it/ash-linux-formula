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
{%- set stigId = 'V38652' %}
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

# Perform action if mount-type is an NFS-type
{%- if fsType == 'nfs' or fsType == 'nfs4' %}

# Grab the option-list for mount
{%- set optList = mountList['opts'] %}
  # See if the mount has the 'nodev' option set
  {%- if 'nodev' in optList %}
notify_{{ stigId }}-{{ mountPoint }}:
  cmd.run:
    - name: 'echo "NFS mount {{ mountPoint }} mounted with ''nodev'' option"'
  {%- else %}
notify_{{ stigId }}-{{ mountPoint }}:
  cmd.run:
    - name: 'echo "NFS mount {{ mountPoint }} not mounted with ''nodev'' option:"'

# Remount with "nodev" option added/set
  {%- set optString = 'nodev,' + ','.join(optList) %}
  {%- set remountDev = mountList['alt_device'] %}
notify_{{ stigId }}-{{ mountPoint }}-remount:
  cmd.run:
    - name: 'printf "\t* Attempting remount...\n"'

remount_{{ stigId }}-{{ mountPoint }}:
  module.run:
    - name: 'mount.remount'
    - m_name: '{{ mountPoint }}'
    - device: '{{ remountDev }}'
    - fstype: '{{ fsType }}'
    - opts: '{{ optString }}'

    # Update fstab (if necessary)
    {%- if salt.file.search('/etc/fstab', '^' + remountDev + '[ 	]') %}
notify_{{ stigId }}-{{ mountPoint }}-fixFstab:
  cmd.run:
    - name: 'printf "\t* Updating /etc/fstab as necessary\n"'

fstab_{{ stigId }}-{{ mountPoint }}:
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
