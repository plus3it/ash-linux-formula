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
{%- set aideCfg = '/etc/aide.conf' %}
{%- set filesToMonitor = [
        "/usr/sbin/auditctl",
        "/usr/sbin/auditd",
        "/usr/sbin/augenrules",
        "/usr/sbin/aureport",
        "/usr/sbin/ausearch",
        "/usr/sbin/autrace",
    ]
%}
{%- set monitorSetting = 'p+i+n+u+g+s+b+acl+xattrs+sha512' %}

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
Ensure {{ aideCfg }} exists ({{ stig_id }}):
  file.managed:
    - name: '{{ aideCfg }}'
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
  {%- for fileToMonitor in filesToMonitor %}
Ensure monitoring of {{ fileToMonitor }} in {{ aideCfg }} ({{ stig_id }}):
  file.replace:
    - name: '{{ aideCfg }}'
    - append_if_not_found: True
    - backup: False
    - not_found_content: |
        # Set per rule {{ stig_id }}
        {{ fileToMonitor }} {{ monitorSetting }}
    - pattern: '^(\s\s*){{ fileToMonitor }}\s\s*p\+i\+n\+u\+g\+s\+b\+acl\+.*'
    - repl: '{{ fileToMonitor }} {{ monitorSetting }}'
    - unless:
      - 'grep -P "^(\s\s*|)/usr/sbin/auditctl\s\s*p\+i\+n\+u\+g\+s\+b\+acl\+.*" {{ aideCfg }}'
    - watch:
      - file: 'Ensure {{ aideCfg }} exists ({{ stig_id }})'
  {%- endfor %}
{%- endif %}
