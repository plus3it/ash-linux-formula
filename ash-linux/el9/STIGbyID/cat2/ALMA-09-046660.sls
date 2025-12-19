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
    'delete_module',
    'finit_module',
    'init_module'
  ]
%}

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
{%- elif osName == 'AlmaLinux' %}
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
