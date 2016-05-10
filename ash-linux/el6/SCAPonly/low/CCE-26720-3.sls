# This Salt test/lockdown implements a SCAP item that has not yet been
# merged into the DISA-published STIGS
#
# Rule ID:
# - mount_option_tmp_noexec
#
# Security identifiers:
# - CCE-26720-3
#
# Rule Summary: Add noexec Option to Removable Media Partitions
#
# Rule Text: The noexec mount option prevents the direct execution of 
#            binaries on the mounted filesystem. Preventing the direct 
#            execution of binaries from removable media (such as a USB 
#            key) provides a defense against malicious software that may 
#            be present on such untrusted media. Add the noexec option 
#            to the fourth column of /etc/fstab for the line which 
#            controls mounting of any removable media partitions.
#
#            Allowing users to execute binaries from removable media 
#            such as USB keys exposes the system to potential compromise.
#
#################################################################

{%- set helperLoc = 'ash-linux/el6/SCAPonly/low/files' %}
{%- set scapId = 'CCE-26720-3' %}

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
  # See if the mount has the 'noexec' option set
  {%- if 'noexec' in optList %}
notify_{{ scapId }}-{{ mountPoint }}:
  cmd.run:
    - name: 'echo "''{{ mountPoint }}'' mounted with ''noexec'' option"'
  {%- else %}
notify_{{ scapId }}-{{ mountPoint }}:
  cmd.run:
    - name: 'echo "''{{ mountPoint }}'' not mounted with ''noexec'' option:"'

# Remount with "noexec" option added/set
  {%- set optString = 'noexec,' + ','.join(optList) %}
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
