# Ref Doc:    STIG - RHEL 8 v1r11
# Finding ID: V-230466
# Rule ID:    SV-230466r627750_rule
# STIG ID:    RHEL-08-030590
# SRG ID:     SRG-OS-000037-GPOS-00015
#             SRG-OS-000042-GPOS-00020
#             SRG-OS-000062-GPOS-00031
#             SRG-OS-000062-GPOS-00031
#             SRG-OS-000392-GPOS-00172
#             SRG-OS-000462-GPOS-00206
#             SRG-OS-000471-GPOS-00215
#             SRG-OS-000473-GPOS-00218
#
# Finding Level: medium
#
# Rule Summary:
#       Successful/unsuccessful modifications to the faillock log file
#       in RHEL 8 must generate an audit record.
#
# References:
#   CCI:
#     - CCI-000169
#         NIST SP 800-53 :: AU-12 a
#         NIST SP 800-53A :: AU-12.1 (ii)
#         NIST SP 800-53 Revision 4 :: AU-12 a
#
###########################################################################
{%- set stig_id = 'RHEL-08-030590' %}
{%- set helperLoc = tpldir ~ '/files' %}
{%- set ruleFile = '/etc/audit/rules.d/logins.rules' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}

{{ stig_id }}-description:
  test.show_notification:
    - text: |
        --------------------------------------
        STIG Finding ID: V-230466
             Modifications to the faillock log
             file must generate an audit
             record
        --------------------------------------

{%- if stig_id in skipIt %}
notify_{{ stig_id }}-skipSet:
  test.show_notification:
    - text: |
        Handler for {{ stig_id }} has been selected for skip.
{%- else %}
Log faillock modifications ({{ stig_id }}):
  file.replace:
    - name: '{{ ruleFile }}'
    - append_if_not_found: True
    - not_found_content: |-

        # Inserted per STIG ID {{ stig_id }}
        -w /var/log/faillock -p wa -k logins
    - pattern: '^(#|)-w\s*\/var\/log\/faillock\s\s*-p\s\s*wa\s\s*-k\s\s*logins'
    - repl: '-w /var/log/faillock -p wa -k logins'
    - unless:
        cmd: 'grep -P ''^(#|)-w\s*\/var\/log\/faillock\s\s*-p\s\s*wa\s\s*-k\s\s*logins'' /etc/audit/rules.d/*'
{%- endif %}
