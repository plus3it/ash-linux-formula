# Ref Doc:    STIG - RHEL 9 v2r4 (29 Apr 2025)
# Finding ID: V-258129
# Rule ID:    SV-258129r958472_rule
# STIG ID:    RHEL-09-611200
# SRG ID:     SRG-OS-000080-GPOS-00048
#
# Finding Level: medium
#
# Rule Summary:
#       RHEL 9 must require authentication to access single-user mode
#
# References:
# NIST SP 800-53 :: AC-3
# NIST SP 800-53 :: CM-6(a)
# NIST SP 800-53 :: IA-2
#
###########################################################################
{%- set stig_id = 'RHEL-09-611200' %}
{%- set helperLoc = tpldir ~ '/files' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}
{%- set cfgFile = '/usr/lib/systemd/system/rescue.service' %}
{%- set fixString = salt.pillar.get('ash-linux:lookup:rescue_shell_protection',
          '/usr/lib/systemd/systemd-sulogin-shell rescue'
        )
%}

{{ stig_id }}-description:
  test.show_notification:
    - text: |
        ----------------------------------------
        STIG Finding ID: V-258129
             The OS must require authentication
             to access single-user mode
        ----------------------------------------

{%- if stig_id in skipIt %}
notify_{{ stig_id }}-skipSet:
  test.show_notification:
    - text: |
        Handler for {{ stig_id }} has been selected for skip.
{%- else %}
Require Authentication for Single User Mode:
  file.replace:
    - name:  '{{ cfgFile }}'
    - pattern: '(^ExecStart=)(.*$)'
    - repl: '\g<1>-{{ fixString }}'

Reload systemctl daemon ({{ stig_id }}):
  module.run:
    - name: service.systemctl_reload
    - watch:
      - file: 'Require Authentication for Single User Mode'

Restart Rescue Service ({{ stig_id }}):
  service.running:
    - name: 'rescue'
    - enable: true
    - reload: false
    - watch:
      - module: 'Reload systemctl daemon ({{ stig_id }})'

{%- endif %}
