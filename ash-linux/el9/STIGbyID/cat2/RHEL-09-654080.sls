# Ref Doc:
#   - STIG - RHEL 9 v2r6      (01 Oct 2025)
#   - STIG - OEL 9 v1r3       (01 Oct 2025)
#   - STIG - AL2023 v1r1      (14 Jul 2025)
# Finding ID:
#   - RHEL:   V-258190
#   - OEL:    V-271565
#   - AL2023: V-274091
# Rule ID:
#   - RHEL:   SV-258190r1106379_rule
#   - OEL:    SV-271565r1092550_rule
#   - AL2023: SV-274091r1120261_rule
# STIG ID:
#   - RHEL:   RHEL-09-654080
#   - OEL:    OL09-00-000690
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
    'AlmaLinux': 'RHEL-09-654080',
    'Amazon': 'AZLX-23-002135',
    'CentOS Stream': 'RHEL-09-654080',
    'OEL': 'OL09-00-000690',
    'RedHat': 'RHEL-09-654080',
    'Rocky': 'RHEL-09-654080',
} %}
{%- set osName = salt.grains.get('os') %}
{%- set stig_id = stigIdByVendor[osName] %}
{%- set helperLoc = tpldir ~ '/files' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}
{%- set cfgFile = '/etc/audit/rules.d/audit.rules' %}
{%- set auditKey = 'module_chng' %}
{%- set auditArchs = [
    'b32',
    'b64'
  ]
%}
{%- set actsToMonitor = [
    'finit_module',
    'init_module'
  ]
%}

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
