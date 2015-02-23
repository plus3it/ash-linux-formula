# This Salt test/lockdown implements a SCAP item that has not yet been
# merged into the DISA-published STIGS
#
# Rule ID:
# - configure_logwatch_splithosts
#
# Security identifiers:
# - CCE-27069-4
#
# Rule Summary: Configure logwatch SplitHosts line
#
# Rule Text: If SplitHosts is set, Logwatch will separate entries by 
#            hostname. This makes the report longer but significantly 
#            more usable. If it is not set, then Logwatch will not 
#            report which host generated a given log entry, and that 
#            information is almost always necessary.
#
#################################################################

{%- set helperLoc = 'ash-linux/SCAPonly/low/files' %}
{%- set scapId = 'CCE-27232-8' %}
{%- set checkFile = '/etc/netconfig' %}
{%- set checkPat = [ 'udp6', 'tcp6' ] %}
{%- set notify_change = '''{{ svcName }}'' has been enabled' %}
{%- set notify_nochange = '''{{ svcName }}'' already enabled' %}

script_{{ scapId }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ scapId }}.sh
    - cwd: '/root'

status_{{ scapId }}-describe:
  cmd.run:
    - name: 'printf "************************************\n*THIS MODULE CURRENTLY INCOMPLETE *\n************************************\n" >& 2'
