# Ref Doc:
#   - STIG - RHEL 9 v2r6      (01 Oct 2025)
#   - STIG - OEL 9 v1r3       (01 Oct 2025)
#   - STIG - AlmaLinux 9 v1r4 (01 Oct 2025)
#   - STIG - AL2023 v1r1      (14 Jul 2025)
# Finding ID:
#   - RHEL:   V-258078
#   - OEL:    V-271452
#   - Alma:   V-269430
#   - AL2023: V-274153
# Rule ID:
#   - RHEL:   SV-258078r958944_rule
#   - OEL:    SV-271452r1091068_rule
#   - Alma:   SV-269430r1050313_rule
#   - AL2023: SV-274153r1120713_rule
# STIG ID:
#   - RHEL-09-431010
#   - OL09-00-000060
#   - ALMA-09-041930
#   - AZLX-23-002450
# SRG ID:
#   - RHEL:   SRG-OS-000445-GPOS-00199
#   - OEL:    SRG-OS-000445-GPOS-00199
#   - Alma:   SRG-OS-000134-GPOS-00068
#   - AL2023: SRG-OS-000134-GPOS-00068
#
# Finding Level: medium
#
# Rule Summary:
#       The OS must use a Linux Security Module configured to enforce limits on system services
#
# References:
#   CCI:
#     - CCI-001084
#     - CCI-002696
#   NIST:
#     - SP 800-53 :: SC-3
#     - SP 800-53A :: SC-3.1 (ii)
#     - SP 800-53 Revision 4 :: SC-3, SI-6 a
#
###########################################################################
{%- set stigIdByVendor = {
    'AlmaLinux': 'ALMA-09-041930',
    'Amazon': 'AZLX-23-002450',
    'CentOS Stream': 'RHEL-09-431010',
    'OEL': 'OL09-00-000060',
    'RedHat': 'RHEL-09-431010',
    'Rocky': 'RHEL-09-431010',
} %}
{%- set stig_id = stigIdByVendor[salt.grains.get('os')] %}
{%- set helperLoc = tpldir ~ '/files' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}
{%- set cfgFile = '/etc/selinux/config' %}
{%- set selMode = salt.pillar.get('ash-linux:lookup:selinux:mode', 'enforcing') %}
{%- set selType = salt.pillar.get('ash-linux:lookup:selinux:type', 'targeted') %}

{{ stig_id }}-description:
  test.show_notification:
    - text: |-
        ----------------------------------------
        STIG Finding ID: {{ stig_id }}
            The OS must use a Linux Security
            Module configured to enforce limits
            on system services
        ----------------------------------------

{%- if stig_id in skipIt %}
notify_{{ stig_id }}-skipSet:
  test.show_notification:
    - text: |
        Handler for {{ stig_id }} has been selected for skip.
{%- else %}
Set SELinux enforcement mode ({{ stig_id }}):
  file.replace:
    - name: '{{ cfgFile }}'
    - append_if_not_found: True
    - not_found_content: |
        # Set per rule {{ stig_id }}
        SELINUX={{ selMode }}
    - pattern: '^(|\s\s*)(SELINUX=).*'
    - repl: '\1{{ selMode }}'

Set SELinux enforcement type ({{ stig_id }}):
  file.replace:
    - name: '{{ cfgFile }}'
    - append_if_not_found: True
    - not_found_content: |
        # Set per rule {{ stig_id }}
        SELINUXTYPE={{ selType }}
    - pattern: '^(|\s\s*)(SELINUXTYPE=).*'
    - repl: '\1{{ selType }}'
{%- endif %}
