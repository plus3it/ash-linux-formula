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
{%- set searchDir = '/etc/audit/rules.d' %}
{%- set auditFileDflt = '/etc/audit/rules.d/audit.rules' %}
{%- set auditFiles = [] + salt.file.find(
      searchDir,
      type='f',
      name='*.rules',
      grep='xattr'
    )
%}
{%- if auditFiles|length == 0 %}
  {%- set auditFiles = [ auditFileDflt ] %}
{%- endif %}
{%- set auditArchs = [
    'b32',
    'b64'
  ]
%}
{%- set auditKey = 'perm_mod' %}
{%- set monitorList = [
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
  {%- for auditFile in auditFiles %}
Ensure {{ auditFile }} file exists ({{ stig_id }}):
  file.managed:
    - name: '{{ auditFile }}'
    - backup: False
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

    {%- for auditArch in auditArchs %}
      {%- set uid0Rule =
           '-a always,exit -F arch=' +
            auditArch +
            ' -S ' +
            monitorList|join(",") +
            ' -F auid=0 -k ' +
            auditKey
      %}
      {%- set unprivRule =
            '-a always,exit -F arch=' +
            auditArch +
            ' -S ' +
            monitorList|join(",") +
            ' -F auid>=1000 -F auid!=unset -k ' +
            auditKey
      %}
      {%- set unprivRuleQuoted =
            '-a always,exit -F arch=' +
            auditArch +
            ' -S ' +
            monitorList|join(",") +
            ' -F "auid>=1000" -F "auid!=unset" -k ' +
            auditKey
      %}
Persistent auditing-setup in {{ auditFile }} for tracking xattr sys-calls by uid 0 on {{ auditArch }} systems ({{ stig_id }}):
  file.replace:
    - name: '{{ auditFile }}'
    - append_if_not_found: True
    - backup: False
    - not_found_content: |
        # Set xattr sys-call tracking for arch={{ auditArch }} per rule {{ stig_id }}
        {{ uid0Rule }}
    - onlyif:
      - '[[ $( find {{ searchDir }} -name "*.rules" | xargs grep -El "xattr.*auid=0" | grep -v "{{ auditFile }}" | wc -l ) == "0" ]]'
    - pattern: '(^(|))(-a always,exit -F arch={{ auditArch }}\s\s*)(-S(\s\s*(([a-z,]*[a-z]*(|,).*xattr)\s\s*)))(.*-F\s\s*auid=0\s\s*.*$)'
    - repl: '{{ uid0Rule }}'
    - watch:
      - file: 'Ensure {{ auditFile }} file exists ({{ stig_id }})'

Persistent auditing-setup in {{ auditFile }} for tracking xattr sys-calls by other than uid 0 on {{ auditArch }} systems ({{ stig_id }}):
  file.replace:
    - name: '{{ auditFile }}'
    - append_if_not_found: True
    - backup: False
    - not_found_content: |
        # Set xattr sys-call tracking for arch={{ auditArch }} per rule {{ stig_id }}
        {{ unprivRule }}
    - onlyif:
      - '[[ $( find {{ searchDir }} -name "*.rules" | xargs grep -Pl "xattr.*auid(|!|>)=1000" | grep -v "{{ auditFile }}" | wc -l ) == "0" ]]'
    - pattern: '(^(|))(-a always,exit -F arch={{ auditArch }}\s\s*)(-S(\s\s*(([a-z,]*[a-z]*(|,).*xattr)\s\s*)))(.*-F\s\s*auid(!|>)=\d*\s\s*.*$)'
    - repl: '{{ unprivRule }}'
    - watch:
      - file: 'Ensure {{ auditFile }} file exists ({{ stig_id }})'

Live auditing-setup in {{ auditFile }} for tracking xattr sys-calls by uid 0 on {{ auditArch }} systems ({{ stig_id }}):
  cmd.run:
    - name: 'auditctl {{ uid0Rule }}'
    - onchanges:
      - file: 'Persistent auditing-setup in {{ auditFile }} for tracking xattr sys-calls by uid 0 on {{ auditArch }} systems ({{ stig_id }})'
    - unless:
      - '[[ $( auditctl -s | awk ''/^enabled /{ print $2 }'' ) == 2 ]]'

Live auditing-setup in {{ auditFile }} for tracking xattr sys-calls by other than uid 0 on {{ auditArch }} systems ({{ stig_id }}):
  cmd.run:
    - name: 'auditctl {{ unprivRuleQuoted }}'
    - onchanges:
      - file: 'Persistent auditing-setup in {{ auditFile }} for tracking xattr sys-calls by other than uid 0 on {{ auditArch }} systems ({{ stig_id }})'
    - unless:
      - '[[ $( auditctl -s | awk ''/^enabled /{ print $2 }'' ) == 2 ]]'
    {%- endfor %}
  {%- endfor %}
{%- endif %}
