# This Salt test/lockdown implements a SCAP item that has already been
# merged into the DISA-published STIGS
#
# Rule ID:
# - rsyslog_send_messages_to_logserver
#
# Security identifiers:
# - CCE-26801-1
#
# Rule Summary: Ensure Logs Sent To Remote Host
#
# Rule Text: A log server (loghost) receives syslog messages from one or 
#            more systems. This data can be used as an additional log 
#            source in the event a system is compromised and its local 
#            logs are suspect. Forwarding log messages to a remote 
#            loghost also provides system administrators with a 
#            centralized place to view the status of multiple hosts 
#            within the enterprise.
#
#################################################################

{%- set helperLoc = 'ash-linux/el6/SCAPonly/low/files' %}
{%- set scapId = 'CCE-26801-1' %}
{%- set stigId = 'V-38521' %}

script_{{ scapId }}-describe:
  cmd.run:
    - name: 'printf "
************************************************\n
* NOTE: {{ scapId }} already covered by handler *\n
*       for STIG-ID {{ stigId }}                    *\n
************************************************\n"'
