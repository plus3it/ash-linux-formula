# Ref Doc:
#   - STIG - RHEL 9 v2r6      (01 Oct 2025)
#   - STIG - OEL 9 v1r3       (01 Oct 2025)
#   - STIG - AlmaLinux 9 v1r4 (01 Oct 2025)
# Finding ID:
#   - RHEL: V-257951
#   - OEL:  V-271763
#   - Alma: V-269252
# Rule ID:
#   - RHEL: SV-257951r1014843_rule
#   - OEL:  SV-271763r1092001_rule
#   - Alma: SV-269252r1050134_rule
# STIG ID:
#   - RHEL-09-252050
#   - OL09-00-002425
#   - ALMA-09-019490
# SRG ID:     SRG-OS-000480-GPOS-00227
#
# Finding Level: medium
#
# Rule Summary:
#       The OS must be configured to prevent unrestricted mail relaying
#
# References:
#   CCI:
#     - CCI-000366
#   NIST:
#     - SP 800-53 :: CM-6 b
#     - SP 800-53A :: CM-6.1 (iv)
#     - SP 800-53 Revision 4 :: CM-6 b
#
###########################################################################
{%- set stigIdByVendor = {
    'AlmaLinux': 'ALMA-09-019490',
    'CentOS Stream': 'RHEL-09-252050',
    'OEL': 'OL09-00-002425',
    'RedHat': 'RHEL-09-252050',
    'Rocky': 'RHEL-09-252050',
} %}
{%- set stig_id = stigIdByVendor[salt.grains.get('os')] %}
{%- set helperLoc = tpldir ~ '/files' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}
{%- set cfgFile = '/etc/postfix/main.cf' %}
{%- set extraOpts = salt.pillar.get('ash-linux:lookup:postfix:main_cf:smtpd_client_restrictions', []) %}
{%- set cfgOptList = ['permit_mynetworks'] + extraOpts + ['reject'] %}

{{ stig_id }}-description:
  test.show_notification:
    - text: |-
        ----------------------------------------
        STIG Finding ID: {{ stig_id }}
            The OS must be configured to prevent
            unrestricted mail relaying
        ----------------------------------------

{%- if stig_id in skipIt %}
notify_{{ stig_id }}-skipSet:
  test.show_notification:
    - text: |
        Handler for {{ stig_id }} has been selected for skip.
{%- elif salt.pkg.version('postfix') %}
Set Postfix Allowed Relay Sources:
  file.replace:
    - name:  '{{ cfgFile }}'
    - append_if_not_found: true
    - not_found_content: 'smtpd_client_restrictions = {{ cfgOptList|join(',') }}'
    - pattern: '(^smtpd_client_restrictions\s\s*)(.*$)'
    - repl: '\g<1>= {{ cfgOptList|join(',') }}'

Postfix Service ({{ stig_id }}):
  service.running:
    - name: 'postfix'
    - enable: true
    - reload: false
    - watch:
        - file: "Set Postfix Allowed Relay Sources"
{%- else %}
Finding Not Valid for {{ stig_id }}:
  test.show_notification:
    - text: |
        Per the STIG's Check Text, "If postfix is not installed, this is Not Applicable"
{%- endif %}
