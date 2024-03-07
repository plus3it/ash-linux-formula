# Ref Doc:    STIG - RHEL 8 v1r7
# Finding ID: V-230355
# Rule ID:    SV-230355r818836_rule
# STIG ID:    RHEL-08-020090
# SRG ID:     SRG-OS-000068-GPOS-00036
#
# Finding Level: medium
#
# Rule Summary:
#       RHEL 8 must map the authenticated identity to the user or group
#       account for PKI-based authentication
#
# References:
#   CCI:
#     - CCI-000187
#   NIST SP 800-53 :: IA-5 (2)
#   NIST SP 800-53A :: IA-5 (2).1
#   NIST SP 800-53 Revision 4 :: IA-5 (2) (c)
#
###########################################################################
{%- set stig_id = 'RHEL-08-020090' %}
{%- set helperLoc = tpldir ~ '/files' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}
