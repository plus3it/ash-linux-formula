# Ref Doc:
#   - STIG - RHEL 9 v2r6      (01 Oct 2025)
#   - STIG - OEL 9 v1r3       (01 Oct 2025)
#   - STIG - AlmaLinux 9 v1r4 (01 Oct 2025)
#   - STIG - AL2023 v1r1      (14 Jul 2025)

# Finding ID:
#   - RHEL:   V-258137
#   - OEL:    V-271569
#   - Alma:   V-269545
#   - AL2023: V-274026
# Rule ID:
#   - RHEL:   SV-258137r1102081_rule
#   - OEL:    SV-271569r1091419_rule
#   - Alma:   SV-269545r1050428_rule
#   - AL2023: SV-274026r1120066_rule
# STIG ID:
#   - RHEL-09-651025
#   - OL09-00-000710
#   - ALMA-09-056890
#   - AZLX-23-NNNNNN
# SRG ID:     SRG-OS-000256-GPOS-00097
#   - SRG-OS-000257-GPOS-00098
#   - SRG-OS-000258-GPOS-00099
#   - SRG-OS-000278-GPOS-00108
#
# Finding Level: medium
#
# Rule Summary:
#       The OS must must use cryptographic mechanisms to protect the integrity
#       of audit tools
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
    'AlmaLinux': 'ALMA-09-056890',
    'Amazon': 'AZLX-23-NNNNNN',
    'CentOS Stream': 'RHEL-09-651025',
    'OEL': 'OL09-00-000710',
    'RedHat': 'RHEL-09-651025',
    'Rocky': 'RHEL-09-651025',
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
            The OS must must use cryptographic
            mechanisms to protect the integrity
            of audit tools
        ----------------------------------------

{%- if stig_id in skipIt %}
notify_{{ stig_id }}-skipSet:
  test.show_notification:
    - text: |
        Handler for {{ stig_id }} has been selected for skip.
{%- else %}
{%- endif %}
