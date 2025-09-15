# Rule ID:              content_rule_postfix_prevent_unrestricted_relay
# Finding Level:        medium
#
# Rule Summary:
#       If unrestricted mail relaying is permitted, unauthorized senders could
#       use this host as a mail relay for the purpose of sending spam or other
#       unauthorized activity.
#
# Identifiers:
#   - content_rule_postfix_prevent_unrestricted_relay
#
# References:
#   - OS-SRG
#     - SRG-OS-000480-GPOS-00227
##################################################################
{%- set stig_id = 'content_rule_postfix_prevent_unrestricted_relay' %}
{%- set helperLoc = tpldir ~ '/files' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}
{%- set cfgFile = '/etc/postfix/main.cf' %}
{%- set extraOpts = salt.pillar.get('ash-linux:lookup:postfix:main_cf:smtpd_client_restrictions', []) %}
{%- set cfgOptList = ['permit_mynetworks'] + extraOpts + ['reject'] %}


{{ stig_id }}-description:
  test.show_notification:
    - text: |
        --------------------------------------
        STIG Finding ID: V-257951
            The SMTP daemon must be configured
            to restrict client-relay sources
        --------------------------------------

{%- if stig_id in skipIt %}
notify_{{ stig_id }}-skipSet:
  test.show_notification:
    - text: |
        Handler for {{ stig_id }} has been selected for skip.
{%- else %}
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
{%- endif %}
