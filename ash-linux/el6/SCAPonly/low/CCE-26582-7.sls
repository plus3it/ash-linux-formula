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
{%- set helperLoc = 'ash-linux/el6/SCAPonly/low/files' %}
{%- set srcMntPt = '/tmp' %}
{%- set dstMntPt = '/var/tmp' %}

# Announce module intent
script_{{ scapId }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ scapId }}.sh
    - cwd: '/root'

# Ensure that '/tmp' is already its own filesystem
{%- if salt['mount.is_mounted'](srcMntPt) %}

  # Ingest list of mounted filesystesm into a searchable-structures
  {%- set activeMntStream = salt['mount.active']('extended=true') %}
  {%- set srcMntStruct = activeMntStream[srcMntPt] %}
  {%- set srcFsType = srcMntStruct['fstype'] %}

notify_{{ scapId }}-{{ srcMntPt }}_ownMount:
  cmd.run:
    - name: 'echo "''{{ srcMntPt }}'' is its own filesystem"'

  # We don't want {{ dstMntPt }} to bind-mount {{ srcMntPt }} if
  # {{ srcMntPt }} is a non-persistent fstype
  {%- if srcFsType == 'tmpfs' %}

notify_{{ scapId }}-donothing:
  cmd.run:
    - name: 'printf "
*******************************************\n
* The {{ srcMntPt }} filesystem is a non-persistent *\n
* fstype. Will not convert {{ dstMntPt }} to a  *\n
* bind-mount of {{ srcMntPt }}                      *\n
*******************************************\n
"'

  # If {{ srcMntPt }} is a persistent fstype, move keep trucking
  {%- else %}

    # If {{ dstMntPt }} is already a mounted volume, we probably
    # shouldn't mess with it
    {%- if salt['mount.is_mounted'](dstMntPt) %}

notify_{{ scapId }}-{{ dstMntPt }}_ownMount:
  cmd.run:
    - name: 'printf "
*******************************************\n
* The {{ dstMntPt }} hierarchy is already on    *\n
* its own mount-point. It would be        *\n
* dangerous to summarily change this.     *\n
*******************************************\n
"'

    # Since {{ dstMntPt }} is not a mounted volume, go ahead
    # And change it to a bind-mount
    {%- else %}

notify_{{ scapId }}-{{ dstMntPt }}_bind:
  cmd.run:
    - name: 'echo "Bind-mounting ''{{ dstMntPt }}'' to {{ srcMntPt }}"'

mount_{{ scapId }}-{{ dstMntPt }}_bind:
  mount.mounted:
    - name: '/var/tmp'
    - device: '/tmp'
    - opts: 'bind'
    - fstype: '{{ srcFsType }}'
    - persist: 'True'

    # End our testing of {{ dstMntPt }} suitability
    {%- endif %}

  # End our testing of {{ srcMntPt }}'s fstype-suitability
  {%- endif %}

# If '/tmp' is not its own mount, this whole exercise is moot
{%- else %}

notify_{{ scapId }}-{{ srcMntPt }}_ownMount:
  cmd.run:
    - name: 'echo "''{{ srcMntPt }}'' is not its own filesystem"'

# End testing for whether {{ srcMntPt }} is its own filesystem
{%- endif %}

