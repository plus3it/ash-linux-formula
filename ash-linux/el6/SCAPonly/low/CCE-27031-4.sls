# This Salt test/lockdown implements a SCAP item that has already been
# merged into the DISA-published STIGS
#
# Rule ID:
# - umask_for_daemons
#
# Security identifiers:
# - CCE-27031-4
#
# Rule Summary: Set Daemon Umask
#
# Rule Text: Setting the umask to too restrictive a setting can cause 
#            serious errors at runtime. Many daemons on the system 
#            already individually restrict themselves to a umask of 077 
#            in their own init scripts.
#     
#            The umask influences the permissions assigned to files 
#            created by a process at run time. An unnecessarily 
#            permissive umask could result in files being created with 
#            insecure permissions.
#
#################################################################

{%- set helperLoc = 'ash-linux/el6/SCAPonly/low/files' %}
{%- set scapId = 'CCE-27031-4' %}
{%- set stigId = 'V-38642' %}

script_{{ scapId }}-describe:
  cmd.run:
    - name: 'printf "
************************************************\n
* NOTE: {{ scapId }} already covered by handler *\n
*       for STIG-ID {{ stigId }}                    *\n
************************************************\n"'
