# Ref Doc:
#   - STIG - AL2023 v1r1      (14 Jul 2025)
# Finding ID:
#   - AL2023: V-274091
# Rule ID:
#   - AL2023: SV-274091r1120261_rule
# STIG ID:
#   - AL2023: AZLX-23-002135
# SRG ID:     SRG-OS-000037-GPOS-00015
#   - SRG-OS-000037-GPOS-00015
#   - SRG-OS-000042-GPOS-00020
#   - SRG-OS-000062-GPOS-00031
#   - SRG-OS-000392-GPOS-00172
#   - SRG-OS-000462-GPOS-00206
#   - SRG-OS-000471-GPOS-00215
#   - SRG-OS-000064-GPOS-00033
#   - SRG-OS-000466-GPOS-00210
#   - SRG-OS-000458-GPOS-00203
#
# Finding Level: medium
#
# Rule Summary:
#       The OS must audit all uses of the init_module and finit_module
#       system calls
#
# References:
#   CCI:
#     - CCI-000130
#   NIST:
#     - SP 800-53 :: AU-3
#     - SP 800-53A :: AU-3.1
#     - SP 800-53 Revision 4 :: AU-3
#
###########################################################################
{%- set stigIdByVendor = {
    'AlmaLinux': 'AZLX-23-002135',
    'Amazon': 'AZLX-23-002135',
    'CentOS Stream': 'AZLX-23-002135',
    'OEL': 'AZLX-23-002135',
    'RedHat': 'AZLX-23-002135',
    'Rocky': 'AZLX-23-002135',
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
            The OS must audit all uses of the
            init_module and finit_module system
            calls
        ----------------------------------------

{%- if stig_id in skipIt %}
notify_{{ stig_id }}-skipSet:
  test.show_notification:
    - text: |
        Handler for {{ stig_id }} has been selected for skip.
{%- else %}
Skip Reason ({{ stig_id }}):
  test.show_notification:
    - text: |-
        ----------------------------------------
        STIG Finding ID: {{ stig_id }}
             Not valid for distro '{{ osName }}'
        ----------------------------------------
{%- endif %}
