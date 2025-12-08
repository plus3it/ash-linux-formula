# Ref Doc:
#   - STIG - AlmaLinux 9 v1r4 (DD MMM YYYY)
# Finding ID:
#   - Alma: V-269391
# Rule ID:
#   - Alma: SV-269391r1050274_rule
# STIG ID:
#   - ALMA-09-036430
# SRG ID:     SRG-OS-000078-GPOS-00046
#
# Finding Level: medium
#
# Rule Summary:
#       The OS must ensure that passwords for new users have a minimum of
#       15 characters
#
# References:
#   CCI:
#     - CCI-000205
#   NIST:
#     - SP 800-53 :: IA-5 (1) (a)
#     - SP 800-53A :: IA-5 (1).1 (i)
#     - SP 800-53 Revision 4 :: IA-5 (1) (a)
#
###########################################################################
{%- set stigIdByVendor = {
    'AlmaLinux': 'ALMA-09-036430',
    'CentOS Stream': 'ALMA-09-036430',
    'OEL': 'ALMA-09-036430',
    'RedHat': 'ALMA-09-036430',
    'Rocky': 'ALMA-09-036430',
} %}
{%- set stig_id = stigIdByVendor[salt.grains.get('os')] %}
{%- set osName = salt.grains.get('os') %}
{%- set helperLoc = tpldir ~ '/files' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}}
{%- set cfgFile = '/etc/login.defs' %}
{%- set minChars = salt.pillar.get('ash-linux:lookup:login_defs:min_pass_len', '15') %}

{{ stig_id }}-description:
  test.show_notification:
    - text: |-
        ----------------------------------------
        STIG Finding ID: {{ stig_id }}
            Passwords for new users must have a
            minimum of 15 characters
        ----------------------------------------

{%- if stig_id in skipIt %}
notify_{{ stig_id }}-skipSet:
  test.show_notification:
    - text: |
        Handler for {{ stig_id }} has been selected for skip.
{%- elif osName == 'AlmaLinux' %}
Set Minimum Password Length to {{ minChars }}:
  file.replace:
    - name: '{{ cfgFile }}'
    - append_if_not_found: True
    - not_found_content: |
        # Set per rule {{ stig_id }}
        PASS_MIN_LEN {{ minChars }}
    - pattern: '(^(|\s\s*))(PASS_MIN_LEN\s\s*)(\d\d*)'
    - repl: 'PASS_MIN_LEN {{ minChars }}'
{%- else %}
Skip Reason ({{ stig_id }}):
  test.show_notification:
    - text: |-
        ----------------------------------------
        STIG Finding ID: {{ stig_id }}
             Not valid for distro '{{ osName }}'
        ----------------------------------------
{%- endif %}
