# Ref Doc:
#   - STIG - RHEL 9 v2r6      (01 Oct 2025)
#   - STIG - OEL 9 v1r3       (01 Oct 2025)
# Finding ID:
#   - RHEL: V-258189
#   - OEL:  V-271564
# Rule ID:
#   - RHEL: SV-258189r1106377_rule
#   - OEL:  SV-271564r1092548_rule
# STIG ID:
#   - RHEL-09-654075
#   - OL09-00-000685
# SRG Group ID: SRG-OS-000037-GPOS-00015
#   - SRG-OS-000037-GPOS-00015
#   - SRG-OS-000042-GPOS-00020
#   - SRG-OS-000062-GPOS-00031
#   - SRG-OS-000392-GPOS-00172
#   - SRG-OS-000462-GPOS-00206
#   - SRG-OS-000471-GPOS-00215
#   - SRG-OS-000471-GPOS-00216
#   - SRG-OS-000477-GPOS-00222
#
# Finding Level: medium
#
# Rule Summary:
#       The OS must audit all uses of the delete_module system call
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
#         - SP 800-53 Revision 4 :: MA-4 (1) (a)`
#
###########################################################################
{%- set stigIdByVendor = {
    'AlmaLinux': 'RHEL-09-654075',
    'Amazon': 'RHEL-09-654075',
    'CentOS Stream': 'RHEL-09-654075',
    'OEL': 'OL09-00-000685',
    'RedHat': 'RHEL-09-654075',
    'Rocky': 'RHEL-09-654075',
} %}
{%- set stig_id = stigIdByVendor[salt.grains.get('os')] %}
{%- set osName = salt.grains.get('os') %}
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
    'delete_module'
  ]
%}

{{ stig_id }}-description:
  test.show_notification:
    - text: |-
        ----------------------------------------
        STIG Finding ID: {{ stig_id }}
            The OS must audit all uses of the
            delete_module system call
        ----------------------------------------

{%- if stig_id in skipIt %}
notify_{{ stig_id }}-skipSet:
  test.show_notification:
    - text: |
        Handler for {{ stig_id }} has been selected for skip.
{%- elif (
    osName != 'AlmaLinux' and
    osName != 'Amazon'
  )
%}
  {%- for actToMonitor in actsToMonitor %}
    {%- for auditArch in auditArchs %}
Audit event "{{ actToMonitor }}" for "{{ auditArch }}" architecture ({{ stig_id }}):
  file.replace:
    - name: '{{ cfgFile }}'
    - append_if_not_found: True
    - not_found_content: |
        # Set per rule {{ stig_id }}
        -a always,exit -F arch={{ auditArch }} -S {{ actToMonitor }} -F auid>=1000 -F auid!=unset -k {{ auditKey }}
    - onchanges_in:
      - cmd: 'Regenerate rules ({{ stig_id }})'
    - pattern: '^(|\s\s*)(-a\s\s*always,exit\s\s*-F\s\s*arch=){{ auditArch }}(\s\s*-S\s\s*){{ actToMonitor }}(\s\s*-F auid>=1000\s\s*-F\s\s*auid!=unset\s\s*-k\s\s*)(module_chng)'
    - repl: '-a always,exit -F arch={{ auditArch }} -S {{ actToMonitor }} -F auid>=1000 -F auid!=unset -k {{ auditKey }}'
    {%- endfor %}
  {%- endfor %}
Regenerate rules ({{ stig_id }}):
  cmd.run:
    - name: 'augenrules --load'
{%- else %}
Skip Reason ({{ stig_id }}):
  test.show_notification:
    - text: |-
        ----------------------------------------
        STIG Finding ID: {{ stig_id }}
             Not valid for distro '{{ osName }}'
        ----------------------------------------
{%- endif %}
