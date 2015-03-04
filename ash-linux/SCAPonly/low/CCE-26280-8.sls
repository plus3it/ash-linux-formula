# This Salt test/lockdown implements a SCAP item that has already been
# merged into the DISA-published STIGS
#
# Rule ID:
# - audit_rules_dac_modification_chmod
#
# Security identifiers:
# - CCE-26280-8
#
# Rule Summary: Record Events that Modify the System's Discretionary
#               Access Controls - chmod
#
# Rule Text: The changing of file permissions could indicate that a user 
#            is attempting to gain access to information that would 
#            otherwise be disallowed. Auditing DAC modifications can 
#            facilitate the identification of patterns of abuse among 
#            both authorized and unauthorized users.
#
#            At a minimum the audit system should collect file 
#            permission changes for all users and root.
#
#################################################################

{%- set helperLoc = 'ash-linux/SCAPonly/low/files' %}
{%- set scapId = 'CCE-26280-8' %}
{%- set stigId = 'V-38543' %}
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
