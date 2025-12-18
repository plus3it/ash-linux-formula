# Ref Doc:
#   - STIG - AlmaLinux 9 v1r4 (01 Oct 2025)
# Finding ID:
#   - Alma: V-269442
# Rule ID:
#   - Alma: SV-269442r1050325_rule
# STIG ID:
#   - ALMA-09-043800
# SRG ID:     SRG-OS-000206-GPOS-00084
#
# Finding Level: medium
#
# Rule Summary:
#       The OS must must not show boot up messages
#
# References:
#   CCI:
#     - CCI-001314
#   NIST:
#     - SP 800-53 :: SI-11 c
#     - SP 800-53A :: SI-11.1 (iv)
#     - SP 800-53 Revision 4 :: SI-11 b
#
###########################################################################
{%- set stigIdByVendor = {
    'AlmaLinux': 'ALMA-09-043800',
    'CentOS Stream': 'ALMA-09-043800',
    'OEL': 'ALMA-09-043800',
    'RedHat': 'ALMA-09-043800',
    'Rocky': 'ALMA-09-043800',
} %}
{%- set stig_id = stigIdByVendor[salt.grains.get('os')] %}
{%- set helperLoc = tpldir ~ '/files' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}

{{ stig_id }}-description:
  test.show_notification:
    - text: |-
        ----------------------------------------
        STIG Finding ID: {{ stig_id }}
            The OS must must not show boot up
            messages
        ----------------------------------------

{%- if stig_id in skipIt %}
notify_{{ stig_id }}-skipSet:
  test.show_notification:
    - text: |
        Handler for {{ stig_id }} has been selected for skip.
{%- else %}
{%- endif %}
