# This Salt test/lockdown implements a SCAP item that has not yet been
# merged into the DISA-published STIGS
#
# Rule ID:
# - 
#
# Security identifiers:
# - CCE-26974-6
#
# Rule Summary: 
#
# Rule Text:
#
#################################################################

{%- set helperLoc = 'ash-linux/SCAPonly/low/files' %}
{%- set scapId = 'CCE-26974-6' %}
{%- set stigId = 'V-38655' %}
{%- set parmName = 'net.ipv6.conf.default.accept_ra' %}
{%- set notify_change = 'In-memory configuration of ''{{ parmName }}'' not disab
led' %}
{%- set notify_nochange = '''{{ parmName }}'' already disabled' %}

script_{{ scapId }}-describe:
  cmd.run:
    - name: 'printf "
************************************************\n
* NOTE: {{ scapId }} already covered by handler *\n
*       for STIG-ID {{ stigId }}                    *\n
************************************************\n"'
