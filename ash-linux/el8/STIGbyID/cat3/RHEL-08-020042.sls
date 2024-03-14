# Ref Doc:    STIG - RHEL 8 v1r7
# Finding ID: V-230350
# Rule ID:    SV-230350r627750_rule
# STIG ID:    RHEL-08-020042
# SRG ID:     SRG-OS-000028-GPOS-00009
#
# Finding Level: low
#
# Rule Summary:
#       The OS must prevent users from disabling session control
#       mechanisms.
#
# References:
#   CCI:
#     - CCI-000056
#   NIST SP 800-53 :: AC-11 b
#   NIST SP 800-53A :: AC-11.1 (iii)
#   NIST SP 800-53 Revision 4 :: AC-11 b
#
###########################################################################
{%- set stig_id = 'RHEL-08-020042' %}
{%- set helperLoc = tpldir ~ '/files' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}
{%- set targFile = '/etc/shells' %}

{{ stig_id }}-description:
  test.show_notification:
    - text: |
        --------------------------------------
        STIG Finding ID: V-230350
            The OS must prevent users diag_out
            from disabling session control
            mechanisms.
        --------------------------------------

{%- if stig_id in skipIt %}
notify_{{ stig_id }}-skipSet:
  test.show_notification:
    - text: |
        Handler for {{ stig_id }} has been selected for skip.
{%- else %}
file_{{ stig_id }}_{{ targFile }}:
  file.replace:
    - name: '{{ targFile }}'
    - pattern: '^/.*/tmux\n'
    - repl: ''
{%- endif %}

