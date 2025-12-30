# Ref Doc:
#   - STIG - RHEL 9 vXrY      (DD MMM YYYY)
#   - STIG - OEL 9 vXrY       (DD MMM YYYY)
#   - STIG - AlmaLinux 9 vXrY (DD MMM YYYY)
# Finding ID:
#   - RHEL: V-NNNNNN
#   - OEL:  V-NNNNNN
#   - Alma: V-NNNNNN
# Rule ID:
#   - RHEL: SV-NNNNNNrNNNNNNN_rule
#   - OEL:  SV-NNNNNNrNNNNNNN_rule
#   - Alma: SV-NNNNNNrNNNNNNN_rule
# STIG ID:
#   - RHEL-09-NNNNNN
#   - OL09-00-NNNNNN
#   - ALMA-09-NNNNNN
# SRG ID:     SRG-OS-NNNNNN-GPOS-NNNNN
#
# Finding Level: medium
#
# Rule Summary:
#       The OS must ...
#
# References:
#   CCI:
#     - CCI-000213
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
{%- set osName = salt.grains.get('os') %}
{%- set stig_id = stigIdByVendor[osName] %}
{%- set helperLoc = tpldir ~ '/files' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}

{{ stig_id }}-description:
  test.show_notification:
    - text: |-
        ----------------------------------------
        STIG Finding ID: {{ stig_id }}
             The OS must ...
        ----------------------------------------

{%- if stig_id in skipIt %}
notify_{{ stig_id }}-skipSet:
  test.show_notification:
    - text: |
        Handler for {{ stig_id }} has been selected for skip.
{%- else %}
{%- endif %}
