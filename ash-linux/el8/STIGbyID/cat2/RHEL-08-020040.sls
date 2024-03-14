# Ref Doc:    STIG - RHEL 8 v1r9
# Finding ID: V-230348
# Rule ID:    SV-230348r880720_rule
# STIG ID:    RHEL-08-020040
# SRG ID:     SRG-OS-000028-GPOS-00009
#             SRG-OS-000030-GPOS-00011
#
# Finding Level: medium
#
# Rule Summary:
#       The operating system must enable a user session lock until that
#       user re-establishes access using established identification and
#       authentication procedures for command line sessions.
#
# References:
#   CCI:
#     - CCI-000056
#   NIST SP 800-53 :: AC-11 b
#   NIST SP 800-53A :: AC-11.1 (iii)
#   NIST SP 800-53 Revision 4 :: AC-11 b
#
###########################################################################
{%- set stig_id = 'RHEL-08-020040' %}
{%- set helperLoc = tpldir ~ '/files' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}
{%- set targFile = '/etc/tmux.conf' %}

{{ stig_id }}-description:
  test.show_notification:
    - text: |
        --------------------------------------
        STIG Finding ID: V-230348
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

{{ targFile }} sets lock-command:
  file.replace:
    - name: '{{ targFile }}'
    - append_if_not_found: True
    - pattern: '^(|#)\s*set\s*.*\slock-command\s*.*'
    - repl: 'set -g lock-command vlock'
    - require:
      - file: '{{ targFile }} Exists'

{{ targFile }} binds X:
  file.replace:
    - name: '{{ targFile }}'
    - append_if_not_found: True
    - pattern: '^(|#)\s*bind\s*.*\s*X\s*lock-session.*$'
    - repl: 'bind X lock-session'
    - require:
      - file: '{{ targFile }} Exists'
{%- endif %}
