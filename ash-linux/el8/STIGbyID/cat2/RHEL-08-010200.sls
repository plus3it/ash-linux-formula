# Ref Doc:    STIG - RHEL 8 v1r9
# Finding ID: V-230244
# Rule ID:    SV-230244r858697_rule
# STIG ID:    RHEL-08-010200
# SRG ID:     SRG-OS-000163-GPOS-00072
#             SRG-OS-000126-GPOS-00066
#             SRG-OS-000279-GPOS-0010
#
# Finding Level: medium
#
# Rule Summary:
#       RHEL 8 must be configured so that all network connections associated
#       with SSH traffic are terminated at the end of the session or after 10
#       minutes of inactivity, except to fulfill documented and validated
#       mission requirements.
#
# References:
#   CCI:
#     - CCI-001133
#   NIST SP 800-53 :: SC-10
#   NIST SP 800-53A :: SC-10.1 (ii)
#   NIST SP 800-53 Revision 4 :: SC-10
#
###########################################################################
{%- set stig_id = 'RHEL-08-010200' %}
{%- set helperLoc = 'ash-linux/el8/STIGbyID/cat2/files' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}

