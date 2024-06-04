# Rule ID:              content_rule_no_tmux_in_shells
# Finding Level:        low
#
# Rule Summary:
#       The tmux terminal multiplexer is used to implement automatic session
#       locking. It should not be listed in /etc/shells.
#
# Identifiers:
#   - content_rule_no_tmux_in_shells
#
# References:
#   - DISA
#     - CCI-000056
#     - CCI-000058
#   - NIST
#     - CM-6
#   - OSPP
#     - FMT_SMF_EXT.1
#     - FMT_MOF_EXT.1
#     - FTA_SSL.1
#   - OS-SRG
#     - SRG-OS-000324-GPOS-00125
#     - SRG-OS-000028-GPOS-00009
#     - SRG-OS-000030-GPOS-00011
#
#################################################################
{%- set stig_id = 'content_rule_no_tmux_in_shells' %}
{%- set helperLoc = tpldir ~ '/files' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}
{%- set cfgFile = '/etc/shells' %}

{{ stig_id }}-description:
  test.show_notification:
    - text: |
        --------------------------------------
        STIG Finding ID: {{ stig_id }}:
          `tmux` should not exist in the
          `/etc/shells` file
        --------------------------------------

{%- if stig_id in skipIt %}
notify_{{ stig_id }}-skipSet:
  test.show_notification:
    - text: |
        Handler for {{ stig_id }} has been selected for skip.
{%- else %}
Ensure tmux not in {{ cfgFile }}:
  file.replace:
    - name: '{{ cfgFile }}'
    - pattern: '^.*/tmux\n'
    - repl: ''
{%- endif %}
