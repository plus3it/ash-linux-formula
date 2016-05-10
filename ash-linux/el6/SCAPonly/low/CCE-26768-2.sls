# This Salt test/lockdown implements a SCAP item that has not yet been
# merged into the DISA-published STIGS
#
# Rule ID:
# - root_path_no_groupother_writable
#
# Security identifiers:
# - CCE-26768-2
#
# Rule Summary: Ensure that root's path does not include world
#               or group-writable directories
#
# Rule Text: Ensure that write permissions are disabled for group and 
#            other on all directories in the root user's PATH. Such 
#            entries increase the risk that root could execute code 
#            provided by unprivileged users, and potentially malicious 
#            code.
#
############################################################

{%- set helperLoc = 'ash-linux/el6/SCAPonly/low/files' %}
{%- set scapId = 'CCE-26768-2' %}
{%- set svcPkg = 'policycoreutils' %}
{%- set svcName = 'restorecond' %}
{%- set notify_change = '''{{ svcName }}'' has been enabled' %}
{%- set notify_nochange = '''{{ svcName }}'' already enabled' %}

script_{{ scapId }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ scapId }}.sh
    - cwd: '/root'

notify_{{ scapId }}-incomplete:
  cmd.run:
    - name: 'printf "************************************\n* THIS MODULE CURRENTLY INCOMPLETE *\n************************************\n" >& 2'

# Does not currently appear to be a Salt-module leverageable for
# this configuration-item. Will need to determine if there's a 
# way for a Salt-executed helper to compute root's interactive-
# PATH, then check each directory's permissions
