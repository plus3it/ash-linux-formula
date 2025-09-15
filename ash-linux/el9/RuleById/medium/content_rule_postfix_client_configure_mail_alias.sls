# Rule ID:              content_rule_postfix_client_configure_mail_alias
# Finding Level:        medium
#
# Rule Summary:
#       Make sure that mails delivered to root user are
#       forwarded to a monitored email address.
#
# Identifiers:
#   - content_rule_postfix_client_configure_mail_alias
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
{%- set emailUserMap = salt.pillar.get('ash-linux:lookup:mail_aliases', {}) %}
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
        -----------------------------------------------------
        Handler for {{ stig_id }} has been selected for skip.
        -----------------------------------------------------
{%- else %}
  {%- if emailUserMap %}
    {%- for mailAliasFile in mailAliasFiles %}
      {%- for key,value in emailUserMap.items() %}
Set email destinations ({{ key }} in {{ mailAliasFile }}):
  file.replace:
    - name: {{ mailAliasFile }}
    - append_if_not_found: true
    - not_found_content: |-
        # Inserted by watchmaker
        {{ key }}: {{ value }}
    - onlyif:
      - '[[ -e {{ mailAliasFile }} ]]'
    - pattern: '^(|#|#\s*|\s*)({{ key }})(\s*:\s*).*$'
    - repl: '\2: {{ value }}'
      {%- endfor %}
    {%- endfor %}
  {%- else %}
Why Skip ({{ stig_id }}) - No Declared email Destinations:
  test.show_notification:
      - text: |
              -------------------------------------------
              CANNOT SET: No `root-mail-dest` value found
                in the ash-linux Pillar-data.
              -------------------------------------------
  {%- endif %}
{%- endif %}
