# Rule ID:              content_rule_network_configure_name_resolution
# Finding Level:        medium
#
# Rule Summary:
#       XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
#
# References:
#   - cis-csc
#     - 12
#     - 15
#     - 8
#   - cobit5
#     - APO13.01
#     - DSS05.02
#   - disa
#     - CCI-000366
#   - isa-62443-2013
#     - SR 3.1
#     - SR 3.5
#     - SR 3.8
#     - SR 4.1
#     - SR 4.3
#     - SR 5.1
#     - SR 5.2
#     - SR 5.3
#     - SR 7.1
#     - SR 7.6
#   - iso27001-2013
#     - A.13.1.1
#     - A.13.2.1
#     - A.14.1.3
#   - nist
#     - SC-20(a)
#     - CM-6(a)
#   - nist-csf
#     - PR.PT-4
#   - os-srg
#     - SRG-OS-000480-GPOS-00227
#     - SRG-OS-000031-GPOS-00012
#
#################################################################
{%- set stig_id = 'configure_redundant_name_resolution' %}
{%- set helperLoc = tpldir ~ '/files' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}

{{ stig_id }}-description:
  test.show_notification:
    - text: |
        --------------------------------------
        STIG Finding ID: {{ stig_id }}
             Hosts should have resilient DNS
             servers configured.
        --------------------------------------

{%- if stig_id in skipIt %}
notify_{{ stig_id }}-skipSet:
  test.show_notification:
    - text: |
        Handler for {{ stig_id }} has been selected for skip.
{%- else %}
# Scanner-notes include the warning:
#   "This rule doesn't come with a remediation, the IP addresses of local
#    authoritative name servers need to be added by the administrator."
Why Skip ({{ stig_id }}):
  test.show_notification:
    - text: |
        --------------------------------------
        NOTE: This handler does nothing because
        there's no good way to determine if
        the client DNS-configuration is
        resiliently-configured or not.

{%- endif %}
