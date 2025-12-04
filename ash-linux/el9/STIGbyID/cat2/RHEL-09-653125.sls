# Ref Doc:
#   - STIG - RHEL 9 v2r6      (01 Oct 2025)
#   - STIG - OEL 9 v1r3       (01 Oct 2025)
#   - STIG - AlmaLinux 9 v1r4 (01 Oct 2025)
# Finding ID:
#   - RHEL: V-258174
#   - OEL:  V-271744
#   - Alma: V-269524
# Rule ID:
#   - RHEL: SV-258174r958424_rule
#   - OEL:  SV-271744r1091944_rule
#   - Alma: SV-269524r1050407_rule
# STIG ID:
#   - RHEL-09-653125
#   - OL09-00-002405
#   - ALMA-09-053920
# SRG ID:     SRG-OS-000046-GPOS-00022
#
# Finding Level: medium
#
# Rule Summary:
#       The OS must must have mail aliases to notify the information system
#       security officer (ISSO) and system administrator (SA) (at a minimum)
#       in the event of an audit processing failure
#
# References:
#   CCI:
#     - CCI-000139
#   NIST:
#     - SP 800-53 :: AU-5 a
#     - SP 800-53A :: AU-5.1 (ii)
#     - SP 800-53 Revision 4 :: AU-5 a
#
###########################################################################
{%- set stigIdByVendor = {
    'AlmaLinux': 'ALMA-09-053920',
    'CentOS Stream': 'RHEL-09-653125',
    'OEL': 'OL09-00-002405',
    'RedHat': 'RHEL-09-653125',
    'Rocky': 'RHEL-09-653125',
} %}
{%- set stig_id = stigIdByVendor[salt.grains.get('os')] %}
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
    - text: |-
        ----------------------------------------
        STIG Finding ID: {{ stig_id }}
             The OS must notify ISSO and SA in
             the event of an audit processing
             failure
        ----------------------------------------

{%- if stig_id in skipIt %}
notify_{{ stig_id }}-skipSet:
  test.show_notification:
    - text: |
        Handler for {{ stig_id }} has been selected for skip.
{%- else %}
  {%- for key,value in emailUserMap.items() %}
Action Description ({{ key }}):
  test.show_notification:
    - text: |
        -------------------------------------------
        Forward emails delivered to {{ key }} user
        to {{ value }}
        -------------------------------------------
    {%- for mailAliasFile in mailAliasFiles %}
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
  {%- else %}
Why Skip ({{ stig_id }}) - No Declared email Destinations:
  test.show_notification:
      - text: |
              -------------------------------------------
              CANNOT SET: No `root-mail-dest` value found
                in the ash-linux Pillar-data.
              -------------------------------------------
  {%- endfor %}
{%- endif %}
