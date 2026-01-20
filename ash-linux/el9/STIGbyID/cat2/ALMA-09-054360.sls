# Ref Doc:
#   - STIG - AlmaLinux 9 vXrY (01 Oct 2025)
# Finding ID:
#   - Alma: V-269528
# Rule ID:
#   - Alma: SV-269528r1050411_rule
# STIG ID:
#   - ALMA-09-054360
# SRG ID:     SRG-OS-000047-GPOS-00023
#
# Finding Level: medium
#
# Rule Summary:
#       The OS must audit system must make full use of the audit storage space
#
# References:
#   CCI:
#     - CCI-000140
#   NIST:
#     - SP 800-53 :: AU-5 b
#     - SP 800-53A :: AU-5.1 (iv)
#     - SP 800-53 Revision 4 :: AU-5 b
#
###########################################################################
{%- set stigIdByVendor = {
    'AlmaLinux': 'ALMA-09-054360',
    'CentOS Stream': 'ALMA-09-054360',
    'OEL': 'ALMA-09-054360',
    'RedHat': 'ALMA-09-054360',
    'Rocky': 'ALMA-09-054360',
} %}
{%- set osName = salt.grains.get('os') %}
{%- set stig_id = stigIdByVendor[osName] %}
{%- set helperLoc = tpldir ~ '/files' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}

{{ stig_id }}-description:
  test.show_notification:
    - text: |-
        ----------------------------------------
        STIG Finding ID: {{ stig_id }}
            The OS must audit system must make
            full use of the audit storage space
        ----------------------------------------

{%- if stig_id in skipIt %}
notify_{{ stig_id }}-skipSet:
  test.show_notification:
    - text: |
        Handler for {{ stig_id }} has been selected for skip.
{%- else %}
{%- endif %}
