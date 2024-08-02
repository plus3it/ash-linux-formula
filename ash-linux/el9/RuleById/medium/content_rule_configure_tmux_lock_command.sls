# Rule ID:              content_rule_configure_tmux_lock_command
# Finding Level:        medium
#
# Rule Summary:
#       The operating system must enable a user session lock until that
#       user re-establishes access using established identification and
#       authentication procedures for command line sessions.
#       `
#
# Identifiers:
#   - content_rule_configure_tmux_lock_command
#
# References:
#   - DISA
#     - CCI-000056
#     - CCI-000058
#   - NIST
#     - AC-11(a)
#     - AC-11(b)
#     - CM-6(a)
#   - OSPP
#     - FMT_SMF_EXT.1
#     - FMT_MOF_EXT.1
#     - FTA_SSL.1
#   - OS-SRG
#     - SRG-OS-000028-GPOS-00009
#     - SRG-OS-000030-GPOS-00011
#
#################################################################
{%- set stig_id = 'configure_tmux_lock_command' %}
{%- set helperLoc = tpldir ~ '/files' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}
{%- set targFile = '/etc/tmux.conf' %}

{{ stig_id }}-description:
  test.show_notification:
    - text: |
        --------------------------------------
        STIG Finding ID: {{ stig_id }}
             The OS must lock user sessions
             until user re-authenticates
        --------------------------------------

{%- if stig_id in skipIt %}
notify_{{ stig_id }}-skipSet:
  test.show_notification:
    - text: |
        Handler for {{ stig_id }} has been selected for skip.
{%- else %}
{{ targFile }} Exists ({{ stig_id }}):
  file.managed:
    - group: 'root'
    - mode: '0644'
    - name: '{{ targFile }}'
    - selinux:
        serange: 's0'
        serole: 'object_r'
        setype: 'etc_t'
        seuser: 'system_u'
    - user: 'root'

{{ targFile }} sets lock-command:
  file.replace:
    - name: '{{ targFile }}'
    - append_if_not_found: True
    - pattern: '^(|#)\s*set\s*.*\slock-command\s*.*'
    - repl: 'set -g lock-command vlock'
    - require:
      - file: '{{ targFile }} Exists ({{ stig_id }})'
{%- endif %}
