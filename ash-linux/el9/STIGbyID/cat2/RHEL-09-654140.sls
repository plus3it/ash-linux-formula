# Ref Doc:
#   - STIG - RHEL 9 v2r6      (01 Oct 2025)
#   - STIG - OEL 9 v1r3       (01 Oct 2025)
#   - STIG - AlmaLinux 9 v1r4 (01 Oct 2025)
# Finding ID:
#   - RHEL: V-258202
#   - OEL:  V-271549
#   - Alma: V-269498
# Rule ID:
#   - RHEL: SV-258202r1045391_rule
#   - OEL:  SV-271549r1092518_rule
#   - Alma: SV-269498r1050381_rule
# STIG ID:
#   - RHEL-09-654140
#   - OL09-00-000610
#   - ALMA-09-050620
# SRG ID:     SRG-OS-000037-GPOS-00015
#   - SRG-OS-000042-GPOS-00020
#   - SRG-OS-000062-GPOS-00031
#   - SRG-OS-000392-GPOS-00172
#   - SRG-OS-000462-GPOS-00206
#   - SRG-OS-000471-GPOS-00215
#
# Finding Level: medium
#
# Rule Summary:
#       The OS must audit all uses of the ssh-keysign command
#
# References:
#   CCI:
#     - CCI-000130
#       NIST:
#         - SP 800-53 :: AU-3
#         - SP 800-53A :: AU-3.1
#         - SP 800-53 Revision 4 :: AU-3
#     - CCI-000135
#       NIST:
#         - SP 800-53 :: AU-3 (1)
#         - SP 800-53A :: AU-3 (1).1 (ii)
#         - SP 800-53 Revision 4 :: AU-3 (1)
#     - CCI-000169
#       NIST:
#         - SP 800-53 :: AU-12 a
#         - SP 800-53A :: AU-12.1 (ii)
#         - SP 800-53 Revision 4 :: AU-12 a
#     - CCI-000172
#       NIST:
#         - SP 800-53 :: AU-12 c
#         - SP 800-53A :: AU-12.1 (iv)
#         - SP 800-53 Revision 4 :: AU-12 c
#     - CCI-002884
#       NIST:
#         - SP 800-53 Revision 4 :: MA-4 (1) (a)
#
###########################################################################
{%- set stigIdByVendor = {
    'AlmaLinux': 'ALMA-09-050620',
    'CentOS Stream': 'RHEL-09-654140',
    'OEL': 'OL09-00-000610',
    'RedHat': 'RHEL-09-654140',
    'Rocky': 'RHEL-09-654140',
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
            ssh-keysign command
        ----------------------------------------

{%- if stig_id in skipIt %}
notify_{{ stig_id }}-skipSet:
  test.show_notification:
    - text: |
        Handler for {{ stig_id }} has been selected for skip.
{%- else %}
{%- endif %}
