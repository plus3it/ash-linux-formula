# Rule ID:              content_rule_configure_usbguard_auditbackend
# Finding Level:        low
#
# Rule Summary:
#       Configure USBGuard daemon to log via Linux Audit service by setting the
#       `AuditBackend` option in the `/etc/usbguard/usbguard-daemon.conf`
#       file to `LinuxAudit`
#
# Identifiers:
#   - content_rule_configure_usbguard_auditbackend
#
# References:
#   - DISA
#     - CCI-000169
#     - CCI-000172
#   - NIST
#     - AU-2
#     - CM-8(3)
#     - IA-3
#   - OSPP
#     - FMT_SMF_EXT.1
#   - OS-SRG
#     - SRG-OS-000062-GPOS-00031
#     - SRG-OS-000471-GPOS-00215
#   - APP-SRG
#     - SRG-APP-000141-CTR-000315
#
#################################################################
{%- set stig_id = 'configure_usbguard_auditbackend' %}
{%- set helperLoc = tpldir ~ '/files' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}
{%- set cfgFile = '/etc/usbguard/usbguard-daemon.conf' %}

{{ stig_id }}-description:
  test.show_notification:
    - text: |
        --------------------------------------
        STIG Finding ID: {{ stig_id }}:
          Configure USBGuard daemon to log via
          Linux Audit service
        --------------------------------------

{%- if stig_id in skipIt %}
notify_{{ stig_id }}-skipSet:
  test.show_notification:
    - text: |
        Handler for {{ stig_id }} has been selected for skip.
{%- else %}
# Ensure file-protections
{{ cfgFile }} - Exists:
  file.managed:
    - name: '{{ cfgFile }}'
    - mode: '0600'
    - user: 'root'
    - group: 'root'
    - selinux:
        serange: 's0'
        serole: 'object_r'
        setype: 'usbguard_conf_t'
        seuser: 'system_u'

# Make config-change
{{ cfgFile }} - Update content:
  file.replace:
    - name: '{{ cfgFile }}'
    - append_if_not_found: True
    - not_found_content: |-
        # Set per rule '{{ stig_id }}'
        AuditBackend=LinuxAudit
    - pattern: '^(|\s*)(AuditBackend)=.*$'
    - repl: '# Set per rule "{{ stig_id }}"\n\2=LinuxAudit'
    - require:
      - file: {{ cfgFile }} - Exists
    - unless:
      - '[[ $( grep AuditBackend=LinuxAudit {{ cfgFile }} ) ]]'

{%- endif %}
