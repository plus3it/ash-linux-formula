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
#            The only legitimate location for device files is the /dev 
#            directory located on the root partition. The only exception 
#            to this is chroot jails.
#
#################################################################

{%- set scapId = 'CCE-26499-4' %}
{%- set helperLoc = 'ash-linux/el6/SCAPonly/low/files' %}

script_{{ scapId }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ scapId }}.sh
    - cwd: '/root'

# Ingest list of mounted filesystesm into a searchable-structure
{%- set mountPoint = '/tmp' %}
{%- set activeMntStream = salt['mount.active']('extended=true') %}
{%- set mountStruct = activeMntStream[mountPoint] %}

{%- if not mountPoint in activeMntStream %}
notify_{{ scapId }}:
  cmd.run:
    - name: 'echo "''{{ mountPoint }}'' is not on its own partition: nothing to do."'
{%- else %}
  # Grab the option-list for mount
  {%- set optList = mountStruct['opts'] %}
  # See if the mount has the 'nodev' option set
  {%- if 'nodev' in optList %}
notify_{{ scapId }}-{{ mountPoint }}:
  cmd.run:
    - name: 'echo "''{{ mountPoint }}'' mounted with ''nodev'' option"'
  {%- else %}
notify_{{ scapId }}-{{ mountPoint }}:
  cmd.run:
    - name: 'echo "''{{ mountPoint }}'' not mounted with ''nodev'' option:"'

# Remount with "nodev" option added/set
  {%- set optString = 'nodev,' + ','.join(optList) %}
  {%- set remountDev = mountStruct['alt_device'] %}
  {%- set fsType = mountStruct['fstype'] %}
notify_{{ scapId }}-{{ mountPoint }}-remount:
  cmd.run:
    - name: 'printf "\t* Attempting remount...\n"'

remount_{{ scapId }}-{{ mountPoint }}:
  module.run:
    - name: 'mount.remount'
    - m_name: '{{ mountPoint }}'
    - device: '{{ remountDev }}'
    - opts: '{{ optString }}'
    - fstype: '{{ fsType }}'

    # Update fstab (if necessary)
    {%- if salt['file.search']('/etc/fstab', '^' + remountDev + '[ 	]') %}
notify_{{ scapId }}-{{ mountPoint }}-fixFstab:
  cmd.run:
    - name: 'printf "\t* Updating /etc/fstab as necessary\n"'

# "file.managed" should work, but we have to use cmd.run, for now
fstab_{{ scapId }}-{{ mountPoint }}-backup:
  cmd.run:
    - name: 'cp /etc/fstab /etc/fstab.`date "+%Y%m%d%H%M"`'

fstab_{{ scapId }}-{{ mountPoint }}:
  mount.mounted:
    - name: '{{ mountPoint }}'
    - device: '{{ remountDev }}'
    - fstype: '{{ fsType }}'
    - opts: '{{ optString }}'
    - mount: True
    - unless: fstab_{{ scapId }}-{{ mountPoint }}-backup

    {%- endif %}
  {%- endif %} 
{%- endif %}
