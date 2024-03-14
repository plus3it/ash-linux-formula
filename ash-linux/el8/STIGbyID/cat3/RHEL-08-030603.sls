# Ref Doc:    STIG - RHEL 8 v1r7
# Finding ID: V-230470
# Rule ID:    SV-230470r744006_rule
# STIG ID:    RHEL-08-030603
# SRG ID:     SRG-OS-000062-GPOS-00031
#
# Finding Level: low
#
# Rule Summary:
#       The OS must enable Linux audit logging for the USBGuard daemon
#
# References:
#   CCI:
#     - CCI-000169
#   NIST SP 800-53 :: AU-12 a
#   NIST SP 800-53A :: AU-12.1 (ii)
#   NIST SP 800-53 Revision 4 :: AU-12 a
#
###########################################################################
{%- set stig_id = 'RHEL-08-030603' %}
{%- set helperLoc = tpldir ~ '/files' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}
{%- set targFile = '/etc/usbguard/usbguard-daemon.conf' %}

{{ stig_id }}-description:
  test.show_notification:
    - text: |
        --------------------------------------
        STIG Finding ID: V-230470
            The OS must enable Linux audit
            logging for the USBGuard daemon
        --------------------------------------

{%- if stig_id in skipIt %}
notify_{{ stig_id }}-skipSet:
  test.show_notification:
    - text: |
        Handler for {{ stig_id }} has been selected for skip.
{%- else %}
file_{{ stig_id }}_{{ targFile }}_managed:
  file.managed:
    - name: '{{ targFile }}'
    - user: 'root'
    - group: 'root'
    - mode: '0600'
    - makedirs: True
    - dir_mode: '0755'

file_{{ stig_id }}_{{ targFile }}_replace:
  file.replace:
    - name: '{{ targFile }}'
    - append_if_not_found: True
    - pattern: '^(#|)\s*AuditBackend(\s*=\s*).*$'
    - repl: 'AuditBackend=LinuxAudit'
    - require:
      - file: file_{{ stig_id }}_{{ targFile }}_managed
{%- endif %}
