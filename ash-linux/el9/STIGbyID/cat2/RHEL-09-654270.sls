# Ref Doc:
#   - STIG - RHEL 9 v2r6      (01 Oct 2025)
#   - STIG - OEL 9 v1r3       (01 Oct 2025)
#   - STIG - AlmaLinux 9 v1r4 (01 Oct 2025)
#   - STIG - AL2023 v1r1      (14 Jul 2025)
# Finding ID:
#   - RHEL:   V-258228
#   - OEL:    V-271885
#   - Alma:   V-269544
#   - AL2023: V-274187
# Rule ID:
#   - RHEL:   SV-258228r991572_rule
#   - OEL:    SV-271885r1092367_rule
#   - Alma:   SV-269544r1050427_rule
#   - AL2023: SV-274187r1120715_rule
# STIG ID:
#   - RHEL-09-654270
#   - OL09-00-008000
#   - ALMA-09-056780
#   - AZLX-23-005000
# SRG ID:     SRG-OS-000462-GPOS-00206
#   - SRG-OS-000057-GPOS-00027
#   - SRG-OS-000058-GPOS-00028
#   - SRG-OS-000059-GPOS-00029
#   - SRG-OS-000475-GPOS-00220
#
# Finding Level: medium
#
# Rule Summary:
#       The OS must audit system must protect logon UIDs from unauthorized change
#
# References:
#   CCI:
#     - CCI-000162
#       NIST:
#         - SP 800-53 :: AU-9
#         - SP 800-53A :: AU-9.1
#         - SP 800-53 Revision 4 :: AU-9
#     - CCI-000163
#       NIST:
#         - SP 800-53 :: AU-9
#         - SP 800-53A :: AU-9.1
#         - SP 800-53 Revision 4 :: AU-9
#     - CCI-000164
#       NIST:
#         - SP 800-53 :: AU-9
#         - SP 800-53A :: AU-9.1
#         - SP 800-53 Revision 4 :: AU-9
#     - CCI-000172
#       NIST:
#         - SP 800-53 :: AU-12 c
#         - SP 800-53A :: AU-12.1 (iv)
#         - SP 800-53 Revision 4 :: AU-12 c
#
###########################################################################
{%- set stigIdByVendor = {
    'AlmaLinux': 'ALMA-09-056780',
    'Amazon': 'AZLX-23-005000',
    'CentOS Stream': 'RHEL-09-654270',
    'OEL': 'OL09-00-008000',
    'RedHat': 'RHEL-09-654270',
    'Rocky': 'RHEL-09-654270',
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
            The OS must audit system must
            protect logon UIDs from unauthorized
            change
        ----------------------------------------

{%- if stig_id in skipIt %}
notify_{{ stig_id }}-skipSet:
  test.show_notification:
    - text: |
        Handler for {{ stig_id }} has been selected for skip.
{%- else %}
{%- endif %}
