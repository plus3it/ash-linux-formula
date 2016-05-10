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
# NOTE: /dev/shm not governed by /etc/fstab.
#
#################################################################

{%- set scapId = 'CCE-26778-1' %}
{%- set helperLoc = 'ash-linux/el6/SCAPonly/low/files' %}

script_{{ scapId }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ scapId }}.sh
    - cwd: '/root'

# Ingest list of mounted filesystesm into a searchable-structure
{%- set mountPoint = '/dev/shm' %}
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

  {%- endif %} 

# Remount with "nodev" option added/set
{%- set optString = 'nodev,' + ','.join(optList) %}
{%- set remountDev = mountPoint %}
{%- set fsType = mountStruct['fstype'] %}

notify_{{ scapId }}-{{ mountPoint }}-remount:
  cmd.run:
    - name: 'printf "\t* Attempting remount...\n"'

# "file.managed" should work, but we have to use cmd.run, for now
fstab_{{ scapId }}-{{ mountPoint }}-backup:
  cmd.run:
    - name: 'cp /etc/fstab /etc/fstab.`date "+%Y%m%d%H%M"`'

fstab_{{ scapId }}-{{ mountPoint }}:
  mount.mounted:
    - name: '{{ mountPoint }}'
    - device: '{{ fsType }}'
    - fstype: '{{ fsType }}'
    - opts: '{{ optString }}'
    - mount: True
    - unless: fstab_{{ scapId }}-{{ mountPoint }}-backup

{%- endif %}
