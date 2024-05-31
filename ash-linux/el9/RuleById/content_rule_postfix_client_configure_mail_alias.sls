# Rule ID:              content_rule_postfix_client_configure_mail_alias
# Finding Level:        medium
#
# Rule Summary:
#       Make sure that mails delivered to root user are
#       forwarded to a monitored email address.
#
# Identifiers:
#   - CONTENT_RULE_POSTFIX_CLIENT_CONFIGURE_MAIL_ALIAS
#
# References:
#   - ANSSI
#     - BP28(R49)
#   - DISA
#     - CCI-000139
#     - CCI-000366
#   - NIST
#     - CM-6(a)
#   - OS-SRG
#     - SRG-OS-000046-GPOS-00022
##################################################################
{%- set stig_id = 'postfix_client_configure_mail_alias' %}
{%- set helperLoc = tpldir ~ '/files' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}
{%- set rootMailDest = salt.pillar.get('ash-linux:lookup:root-mail-dest', []) %}
{%- set profileFile ='/etc/profile.d/tmux.sh' %}
{%- set mailAliasFiles = [
  '/etc/aliases',
  '/etc/mail/aliases',
  ]
%}

{{ stig_id }}-description:
  test.show_notification:
    - text: |
        -------------------------------------------
        Make sure that mails delivered to root user
        are forwarded to a monitored email address.
        -------------------------------------------

{%- if stig_id in skipIt %}
notify_{{ stig_id }}-skipSet:
  test.show_notification:
    - text: |
        Handler for {{ stig_id }} has been selected for skip.
{%- else %}
  {%- if rootMailDest %}
    {%- for mailAliasFile in mailAliasFiles %}
Set root-mail Destination:
  file.replace:
      - name: '{{ mailAliasFile }}'
      - pattern: '^([rR][oO][oO][tT]|\"[rR][oO][oO][tT]\")\s*:\s*(.+)$'
      - repl: '\1\2{{ rootMailDest }}'
    {%- endfor %}
  {%- else %}
No Declared root-mail Destination:
  test.show_notification:
      - text: |
              -------------------------------------------
              CANNOT SET: No `root-mail-dest` value found
                in the ash-linux Pillar-data.
              -------------------------------------------
  {%- endif %}
{%- endif %}
