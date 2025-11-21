# Ref Doc:
#   - STIG - RHEL 9 v2r5      (02 Jul 2025)
#   - STIG - OEL 9 v1r2       (02 Jul 2025)
#   - STIG - AlmaLinux 9 v1r3 (02 Jul 2025)
# Finding ID:
#   - RHEL: V-NNNNNN
#   - OEL:  V-NNNNNN
#   - Alma: V-NNNNNN
# Rule ID:
#   - RHEL: SV-258129r1117265_rule
#   - OEL:  SV-271442r1091038_rule
#   - Alma: SV-269139r1050021_rule
# STIG ID:
#   - RHEL-09-NNNNNN
#   - OL09-00-NNNNNN
#   - ALMA-09-NNNNNN
# SRG ID:   SRG-OS-000095-GPOS-00049
#
# Finding Level: medium
#
# Rule Summary:
#       <RULE_SUMMARY_TEXT>
#
# References:
#   CCI:
#     - CCI-NNNNNN
#   NIST:
#     - SP 800-53 :: 
#     - SP 800-53A ::
#     - SP 800-53 Revision 4 :: 
#
###########################################################################
{%- set stigIdByVendor = {
    'AlmaLinux': 'ALMA-09-NNNNNN',
    'CentOS Stream': 'RHEL-09-NNNNNN',
    'OEL': 'OL09-00-NNNNNN',
    'RedHat': 'RHEL-09-NNNNNN',
    'Rocky': 'RHEL-09-NNNNNN',
} %}
{%- set stig_id = stigIdByVendor[salt.grains.get('os')] %}
{%- set helperLoc = tpldir ~ '/files' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}

{{ stig_id }}-description:
  test.show_notification:
    - text: |-
        ----------------------------------------
        STIG Finding ID: {{ stig_id }}
             <RULE_SUMMARY_TEXT>
        ----------------------------------------

{%- if stig_id in skipIt %}
notify_{{ stig_id }}-skipSet:
  test.show_notification:
    - text: |
        Handler for {{ stig_id }} has been selected for skip.
{%- else %}
{%- endif %}
