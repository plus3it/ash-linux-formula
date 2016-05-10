# This Salt test/lockdown implements a SCAP item that has not yet been
# merged into the DISA-published STIGS
#
# Rule ID:
# - sysctl_net_ipv4_conf_default_secure_redirects
#
# Security identifiers:
# - CCE-26831-8
#
# Rule Summary: Disable Kernel Parameter for Accepting Secure Redirects
#               By Default
#
# Rule Text: Accepting "secure" ICMP redirects (from those gateways 
#            listed as default gateways) has few legitimate uses. It 
#            should be disabled unless it is absolutely required.
#
#################################################################

{%- set helperLoc = 'ash-linux/el6/SCAPonly/low/files' %}
{%- set scapId = 'CCE-26831-8' %}
{%- set stigId = 'V-38532' %}

script_{{ scapId }}-describe:
  cmd.run:
    - name: 'printf "
************************************************\n
* NOTE: {{ scapId }} already covered by handler *\n
*       for STIG-ID {{ stigId }}                    *\n
************************************************\n"'
