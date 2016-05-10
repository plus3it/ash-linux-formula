# This Salt test/lockdown implements a SCAP item that has not yet been
# merged into the DISA-published STIGS
#
# Security identifiers:
# - CCE-26872-2
#
# Rule ID: no_files_unowned_by_group
#
# Rule Summary: Ensure All Files Are Owned by a Group
#
# Rule Text: If any files are not owned by a group, then the cause of 
#            their lack of group-ownership should be investigated. 
#            Following this, the files should be deleted or assigned to 
#            an appropriate group.
#
#            Unowned files do not directly imply a security problem, but 
#            they are generally a sign that something is amiss. They may 
#            be caused by an intruder, by incorrect software 
#            installation or draft software removal, or by failure to 
#            remove all files belonging to a deleted account. The files 
#            should be repaired so they will not cause problems when 
#            accounts are created in the future, and the cause should be 
#            discovered and addressed.
#
#################################################################

{%- set scapId = 'CCE-26872-2' %}
{%- set helperLoc = 'ash-linux/el6/SCAPonly/low/files' %}
{%- set fsDrv = 'udf' %}
{%- set moduleConf = '/etc/modprobe.d/' + fsDrv + '.conf' %}

script_{{ scapId }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ scapId }}.sh
    - cwd: '/root'

script_{{ scapId }}-grpOwn:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ scapId }}_helper.sh
    - cwd: '/root'

