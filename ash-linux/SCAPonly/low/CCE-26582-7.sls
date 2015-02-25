# This Salt test/lockdown implements a SCAP item that has not yet been
# merged into the DISA-published STIGS
#
# Security identifiers:
# - CCE-26582-7
#
# Rule ID: mount_option_var_tmp_bind_var
#
# Rule Summary: Bind Mount /var/tmp To /tmp
#
# Rule Text: Having multiple locations for temporary storage is not 
#            required. Unless absolutely necessary to meet requirements, 
#            the storage location /var/tmp should be bind mounted to 
#            /tmp and thus share the same protections.
#
#            The /var/tmp directory is a world-writable directory. 
#            Bind-mount it to /tmp in order to consolidate temporary 
#            storage into one location protected by the same techniques 
#            as /tmp.
#
#################################################################

{%- set scapId = 'CCE-26582-7' %}
{%- set helperLoc = 'ash-linux/SCAPonly/low/files' %}
{%- set mountPoint = '/tmp' %}

script_{{ scapId }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ scapId }}.sh
    - cwd: '/root'

#   /tmp:
#       ----------
#       alt_device:
#           tmpfs
#       device:
#           tmpfs
#       fstype:
#           tmpfs
#       opts:
#           - rw
#           - rootcontext=system_u:object_r:tmp_t:s0
#           - seclabel
#           - nosuid
#           - nodev
#           - noexec
#           - relatime


{%- if salt['mount.is_mounted'](mountPoint) %}

  # Ingest list of mounted filesystesm into a searchable-structures
  {%- set activeMntStream = salt['mount.active']('extended=true') %}
  {%- set mountStruct = activeMntStream[mountPoint] %}
  {%- set fsType = mountStruct['fstype'] %}

notify_{{ scapId }}-{{ mountPoint }}_ownMount:
  cmd.run:
    - name: 'echo "''{{ mountPoint }}'' is its own filesystem"'

{%- else %}

notify_{{ scapId }}-{{ mountPoint }}_ownMount:
  cmd.run:
    - name: 'echo "''{{ mountPoint }}'' is not its own filesystem"'

{%- endif %}

