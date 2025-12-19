# Ref Doc:
#   - STIG - AlmaLinux 9 v1r4 (01 Oct 2025)
# Finding ID:
#   - Alma: V-269466
# Rule ID:
#   - Alma: SV-269466r1050349_rule
# STIG ID:
#   - ALMA-09-046660
# SRG ID:
#   - SRG-OS-000471-GPOS-00216
#   - SRG-OS-000477-GPOS-00222
#
# Finding Level: medium
#
# Rule Summary:
#       The OS must audit all uses of the delete_module, init_module and
#       finit_module system calls
#
# References:
#   CCI:
#     - CCI-000213
#   NIST:
#     - SP 800-53 :: AU-12 c
#     - SP 800-53A :: AU-12.1 (iv)
#     - SP 800-53 Revision 4 :: AU-12 c
#
###########################################################################
{%- set stigIdByVendor = {
    'AlmaLinux': 'ALMA-09-046660',
    'CentOS Stream': 'ALMA-09-046660',
    'OEL': 'ALMA-09-046660',
    'RedHat': 'ALMA-09-046660',
    'Rocky': 'ALMA-09-046660',
    'Amazon': 'ALMA-09-046660'
} %}
{%- set stig_id = stigIdByVendor[salt.grains.get('os')] %}
{%- set helperLoc = tpldir ~ '/files' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}

{{ stig_id }}-description:
  test.show_notification:
    - text: |-
        ----------------------------------------
        STIG Finding ID: {{ stig_id }}
            OS must audit all uses of the
            delete_module, init_module and
            finit_module system calls
        ----------------------------------------

{%- if stig_id in skipIt %}
notify_{{ stig_id }}-skipSet:
  test.show_notification:
    - text: |
        Handler for {{ stig_id }} has been selected for skip.
{%- else %}
{%- endif %}
