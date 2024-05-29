# Rule ID:              content_rule_configure_tmux_lock_after_time
# Finding Level:        medium
#
# Rule Summary:
#       To enable console screen locking in tmux terminal multiplexer after a
#       period of inactivity, the lock-after-time option has to be set to a
#       value greater than 0 and less than or equal to 900 in /etc/tmux.conf.
#
# Identifiers:
#   - content_rule_configure_tmux_lock_after_time
#
# References:
#   - DISA
#     - CCI-000057
#     - CCI-000060
#   - OSPP
#     - FMT_SMF_EXT.1
#     - FMT_MOF_EXT.1
#     - FTA_SSL.1
#   - OS-SRG
#     - SRG-OS-000029-GPOS-00010
#     - SRG-OS-000031-GPOS-00012
#
#################################################################
{%- set stig_id = 'configure_tmux_lock_after_time' %}
{%- set helperLoc = tpldir ~ '/files' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}
{%- set lockAfterSec = '900' %}
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
{{ targFile }} Exists:
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

{{ targFile }} sets lock-after-time:
  file.replace:
    - name: '{{ targFile }}'
    - append_if_not_found: True
    - pattern: '^(|#)\s*set\s*.*\slock-after-time\s*.*'
    - repl: 'set -g lock-after-time {{ lockAfterSec }}'
    - require:
      - file: '{{ targFile }} Exists'
{%- endif %}
