# Ref Doc:
#   - STIG - OEL 9 v1r3       (01 Oct 2025)
#   - STIG - AlmaLinux 9 v1r4 (01 Oct 2025)
# Finding ID:
#   - OEL:  V-271597
#   - Alma: V-269512
# Rule ID:
#   - OEL:  SV-271597r1092586_rule
#   - Alma: SV-269512r1050395_rule
# STIG ID:
#   - OL09-00-000855
#   - ALMA-09-052490
# SRG ID:     SRG-OS-NNNNNN-GPOS-NNNNN
#
# Finding Level: medium
#
# Rule Summary:
#       The OS must be configured to offload audit records onto a different
#       system from the system being audited via syslog
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
    'AlmaLinux': 'ALMA-09-052490',
    'CentOS Stream': 'ALMA-09-052490',
    'OEL': 'OL09-00-000855',
    'RedHat': 'ALMA-09-052490',
    'Rocky': 'ALMA-09-052490',
} %}
{%- set osName = salt.grains.get('os') %}
{%- set stig_id = stigIdByVendor[osName] %}
{%- set helperLoc = tpldir ~ '/files' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}
{%- set cfgFile = '/etc/audit/plugins.d/syslog.conf' %}

{{ stig_id }}-description:
  test.show_notification:
    - text: |-
        ----------------------------------------
        STIG Finding ID: {{ stig_id }}
            The OS must offload audit records to
            a remote system via syslog
        ----------------------------------------

{%- if stig_id in skipIt %}
notify_{{ stig_id }}-skipSet:
  test.show_notification:
    - text: |
        Handler for {{ stig_id }} has been selected for skip.
{%- elif
  (
    osName == "AlmaLinux" or
    osName == "OEL"
  )
%}
Ensure the audispd plugins are installed:
  pkg.installed:
    - name: audispd-plugins

Ensure the plugin-file is installed with proper permissions:
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
    - unless:
      - 'test -e {{ cfgFile }}'
    - user: 'root'
    - watch:
      - pkg: 'Ensure the audispd plugins are installed'

Ensure STIG-setting is present:
  file.replace:
    - name: '{{ cfgFile }}'
    - append_if_not_found: True
    - not_found_content: |
        # Set per rule {{ stig_id }}
        active = yes
    - pattern: '^(|\s\s*)(active\s*=)(\s*).*$'
    - repl: '\1\2\3yes'
    - watch:
      - file: 'Ensure the plugin-file is installed with proper permissions'
{%- else %}
Skip Reason ({{ stig_id }}):
  test.show_notification:
    - text: |-
        ----------------------------------------
        STIG Finding ID: {{ stig_id }}
            Not valid for distro '{{ osName }}'
        ----------------------------------------
{%- endif %}
