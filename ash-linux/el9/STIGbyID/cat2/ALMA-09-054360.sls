# Ref Doc:
#   - STIG - AlmaLinux 9 vXrY (01 Oct 2025)
# Finding ID:
#   - Alma: V-269528
# Rule ID:
#   - Alma: SV-269528r1050411_rule
# STIG ID:
#   - ALMA-09-054360
# SRG ID:     SRG-OS-000047-GPOS-00023
#
# Finding Level: medium
#
# Rule Summary:
#       The OS must audit system must make full use of the audit storage space
#
# References:
#   CCI:
#     - CCI-000140
#   NIST:
#     - SP 800-53 :: AU-5 b
#     - SP 800-53A :: AU-5.1 (iv)
#     - SP 800-53 Revision 4 :: AU-5 b
#
###########################################################################
{%- set stigIdByVendor = {
    'AlmaLinux': 'ALMA-09-054360',
    'CentOS Stream': 'ALMA-09-054360',
    'OEL': 'ALMA-09-054360',
    'RedHat': 'ALMA-09-054360',
    'Rocky': 'ALMA-09-054360',
} %}
{%- set osName = salt.grains.get('os') %}
{%- set stig_id = stigIdByVendor[osName] %}
{%- set helperLoc = tpldir ~ '/files' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}
{%- set cfgFile = '/etc/audit/auditd.conf' %}
{%- set cfgParm = 'max_log_file' %}
{%- set cfgValue = salt.pillar.get(
    'ash-linux:lookup:auditd_config:max_log_file',
    '8'
  )
%}

{{ stig_id }}-description:
  test.show_notification:
    - text: |-
        ----------------------------------------
        STIG Finding ID: {{ stig_id }}
            The OS must audit system must make
            full use of the audit storage space
        ----------------------------------------

{%- if stig_id in skipIt %}
notify_{{ stig_id }}-skipSet:
  test.show_notification:
    - text: |
        Handler for {{ stig_id }} has been selected for skip.
{%- elif osName == 'AlmaLinux' %}
Make full use of the audit storage space ({{ stig_id }}):
  file.replace:
    - name: '{{ cfgFile }}'
    - append_if_not_found: True
    - not_found_content: |
        # Set per rule {{ stig_id }}
        {{ cfgParm }} = {{ cfgValue }}
    - pattern: '^((\s\s*|)max_log_file(\s\s*|)=(\s\s*|))\d*'
    - repl: '\g<1>{{ cfgValue }}'
{%- else %}
Skip Reason ({{ stig_id }}):
  test.show_notification:
    - text: |-
        ----------------------------------------
        STIG Finding ID: {{ stig_id }}
             Not valid for distro '{{ osName }}'
        ----------------------------------------
{%- endif %}
