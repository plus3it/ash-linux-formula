# This Salt test/lockdown implements a SCAP item that has already been
# merged into the DISA-published STIGS
#
# Rule ID:
# - audit_rules_dac_modification_lremovexattr
#
# Security identifiers:
# - CCE-27182-5
#
# Rule Summary: Record Events that Modify the System's Discretionary
#               Access Controls
#
# Rule Text:
#
#################################################################

{%- set helperLoc = 'ash-linux/el6/SCAPonly/low/files' %}
{%- set scapId = 'CCE-27182-5' %}
{%- set stigId = 'V-38559' %}

script_{{ scapId }}-describe:
  cmd.run:
    - name: 'printf "
************************************************\n
* NOTE: {{ scapId }} already covered by handler *\n
*       for STIG-ID {{ stigId }}                    *\n
************************************************\n"'
