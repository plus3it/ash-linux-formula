# This Salt test/lockdown implements a SCAP item that has not yet been
# merged into the DISA-published STIGS
#
# Security identifiers:
# - CCE-26622-1
#
# Rule Summary: Set 'noexec' option on '/dev/shm' partition
#
# Rule Text: The noexec mount option can be used to prevent binaries 
#            from being executed out of /dev/shm. It can be dangerous to 
#            allow the execution of binaries from world-writable 
#            temporary storage directories such as /dev/shm. Add the 
#            noexec option to the fourth column of /etc/fstab for the 
#            line which controls mounting of /dev/shm.
#
#            Allowing users to execute binaries from world-writable 
#            directories such as /dev/shm can expose the system to 
#            potential compromise.
#
#################################################################

{%- set scapId = 'CCE-26622-1' %}
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
  # See if the mount has the 'noexec' option set

  {%- if 'noexec' in optList %}

notify_{{ scapId }}-{{ mountPoint }}:
  cmd.run:
    - name: 'echo "''{{ mountPoint }}'' mounted with ''noexec'' option"'

  {%- else %}

notify_{{ scapId }}-{{ mountPoint }}:
  cmd.run:
    - name: 'echo "''{{ mountPoint }}'' not mounted with ''noexec'' option:"'

  {%- endif %} 

# Remount with "noexec" option added/set
{%- set optString = 'noexec,' + ','.join(optList) %}
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
