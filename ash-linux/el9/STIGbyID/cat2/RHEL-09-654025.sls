# Ref Doc:
#   - STIG - RHEL 9 v2r6      (01 Oct 2025)
#   - STIG - OEL 9 v1r3       (01 Oct 2025)
#   - STIG - AlmaLinux 9 v1r4 (01 Oct 2025)
#   - STIG - AL2023 v1r1      (14 Jul 2025)
# Finding ID:
#   - RHEL:   V-258179
#   - OEL:    V-271536
#   - Alma:   V-269505
#   - AL2023: V-274089
# Rule ID:
#   - RHEL:   SV-258179r1106371_rule
#   - OEL:    SV-271536r1092492_rule
#   - Alma:   SV-269505r1050388_rule
#   - AL2023: SV-274089r1120255_rule
# STIG ID:
#   - RHEL-09-654025
#   - OL09-00-000545
#   - ALMA-09-051390
#   - AZLX-23-002125
# SRG ID:     SRG-OS-000037-GPOS-00015
#   - SRG-OS-000042-GPOS-00020
#   - SRG-OS-000062-GPOS-00031
#   - SRG-OS-000392-GPOS-00172
#   - SRG-OS-000458-GPOS-00203
#   - SRG-OS-000462-GPOS-00206
#   - SRG-OS-000463-GPOS-00207
#   - SRG-OS-000471-GPOS-00215
#   - SRG-OS-000474-GPOS-00219
#   - SRG-OS-000466-GPOS-00210
#   - SRG-OS-000064-GPOS-00033
#
# Finding Level: medium
#
# Rule Summary:
#       The OS must audit all uses of the setxattr, fsetxattr, lsetxattr,
#       removexattr, fremovexattr, and lremovexattr system calls
#
# References:
#   CCI:
#     - CCI-000130
#       NIST:
#         - SP 800-53 :: AU-3
#         - SP 800-53A :: AU-3.1
#         - SP 800-53 Revision 4 :: AU-3
#   CCI:
#     - CCI-000135
#       NIST:
#         - SP 800-53 :: AU-3 (1)
#         - SP 800-53A :: AU-3 (1).1 (ii)
#         - SP 800-53 Revision 4 :: AU-3 (1)
#   CCI:
#     - CCI-000169
#       NIST:
#         - SP 800-53 :: AU-12 a
#         - SP 800-53A :: AU-12.1 (ii)
#         - SP 800-53 Revision 4 :: AU-12 a
#   CCI:
#     - CCI-000172
#       NIST:
#         - SP 800-53 :: AU-12 c
#         - SP 800-53A :: AU-12.1 (iv)
#         - SP 800-53 Revision 4 :: AU-12 c
#   CCI:
#     - CCI-002884
#       NIST:
#         - SP 800-53 Revision 4 :: MA-4 (1) (a)
#
###########################################################################
{%- set stigIdByVendor = {
    'AlmaLinux': 'ALMA-09-051390',
    'Amazon': 'AZLX-23-002125',
    'CentOS Stream': 'RHEL-09-654025',
    'OEL': 'OL09-00-000545',
    'RedHat': 'RHEL-09-654025',
    'Rocky': 'RHEL-09-654025',
} %}
{%- set osName = salt.grains.get('os') %}
{%- set stig_id = stigIdByVendor[osName] %}
{%- set helperLoc = tpldir ~ '/files' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}
{%- set cfgFile = '/etc/audit/rules.d/audit.rules' %}
{%- set auditArchs = [
    'b32',
    'b64'
  ]
%}
{%- set auditKey = 'perm_mod' %}
{%- set actsToMonitor = [
    'fremovexattr',
    'fsetxattr',
    'lremovexattr',
    'lsetxattr',
    'removexattr',
    'setxattr',
  ]
%}

{{ stig_id }}-description:
  test.show_notification:
    - text: |-
        ----------------------------------------
        STIG Finding ID: {{ stig_id }}
            The OS must audit all uses of the
            setxattr, fsetxattr, lsetxattr,
            removexattr, fremovexattr, and
            lremovexattr system calls
        ----------------------------------------

{%- if stig_id in skipIt %}
notify_{{ stig_id }}-skipSet:
  test.show_notification:
    - text: |
        Handler for {{ stig_id }} has been selected for skip.
{%- else %}
Ensure {{ cfgFile }} file exists ({{ stig_id }}):
  file.managed:
    - name: '{{ cfgFile }}'
    - create: True
    - group: 'root'
    - mode: '0600'
    - replace: False
    - selinux:
        serange: 's0'
        serole: 'object_r'
        setype: 'auditd_etc_t'
        seuser: 'system_u'
    - user: 'root'
  {%- for actToMonitor in actsToMonitor %}
    {%- for auditArch in auditArchs %}
Persistent auditing-setup for tracking {{ actToMonitor }} sys-calls by uid 0 on {{ auditArch }} systems ({{ stig_id }}):
  file.replace:
    - name: '{{ cfgFile }}'
    - append_if_not_found: True
    - not_found_content: |
        # Set per rule {{ stig_id }}
        -a always,exit -F arch={{ auditArch }} -S {{ actToMonitor }} -F auid=0 -k {{ auditKey }}
    - pattern: '(^(|))(-a always,exit -F arch={{ auditArch }}\s\s*)(-S(\s\s*(([a-z,]*[a-z]*(|,){{ actToMonitor }}.*xattr|{{ actToMonitor }})\s\s*)))(.*-F\s\s*auid=0\s\s*.*$)'
    - repl: '-a always,exit -F arch={{ auditArch }} -S {{ actToMonitor }} -F auid=0 -k {{ auditKey }}'
    - watch:
      - file: 'Ensure {{ cfgFile }} file exists ({{ stig_id }})'

Live auditing-setup for tracking {{ actToMonitor }} sys-calls by uid 0 on {{ auditArch }} systems ({{ stig_id }}):
  cmd.run:
    - name: 'auditctl -a always,exit -F arch={{ auditArch }} -S {{ actToMonitor }} -F auid=0 -k {{ auditKey }}'
    - onchanges:
      - file: 'Persistent auditing-setup for tracking {{ actToMonitor }} sys-calls by uid 0 on {{ auditArch }} systems ({{ stig_id }})'
    - unless:
      - '[[ $( auditctl -s | awk ''/^enabled /{ print $2 }'' ) == 2 ]]'
    {%- endfor %}
  {%- endfor %}
{%- endif %}
