# Ref Doc:
#   - STIG - RHEL 9 v2r5      (02 Jul 2025)
#   - STIG - OEL 9 v1r2       (02 Jul 2025)
#   - STIG - AlmaLinux 9 v1r3 (02 Jul 2025)
# Finding ID:
#   - RHEL: V-258129
#   - OEL:  V-271442
#   - Alma: V-269139
# Rule ID:
#   - RHEL: SV-258129r1117265_rule
#   - OEL:  SV-271442r1091038_rule
#   - Alma: SV-269139r1050021_rule
# STIG ID:
#   - RHEL-09-611200
#   - OL09-00-000030
#   - ALMA-09-006510
# SRG ID:     SRG-OS-000080-GPOS-00048
#
# Finding Level: medium
#
# Rule Summary:
#       The OS must require authentication to access single-user mode
#
# References:
#   CCI:
#     - CCI-000213
#   NIST:
#     - SP 800-53 :: AC-3
#     - SP 800-53A :: AC-3.1
#     - SP 800-53 Revision 4 :: AC-3
#
###########################################################################
{%- set stigIdByVendor = {
    'AlmaLinux': 'ALMA-09-006510',
    'CentOS Stream': 'RHEL-09-611200',
    'OEL': 'OL09-00-000030',
    'RedHat': 'RHEL-09-611200',
    'Rocky': 'RHEL-09-611200',
} %}
{%- set stig_id = stigIdByVendor[salt.grains.get('os')] %}
{%- set helperLoc = tpldir ~ '/files' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}
{%- set cfgFiles = [
    '/usr/lib/systemd/system/rescue.service'
  ]
%}
{%- if salt.file.directory_exists("/etc/systemd/system/rescue.service.d") %}
  {%- do cfgFiles.extend(
      salt.file.find(
        '/etc/systemd/system/rescue.service.d',
	type='f',
	name='*.conf',
	grep='sulogin'
      )
    )
  %}
{%- endif %}
{%- set fixString = salt.pillar.get(
    'ash-linux:lookup:rescue_shell_protection',
    '/usr/lib/systemd/systemd-sulogin-shell rescue'
  )
%}

{{ stig_id }}-description:
  test.show_notification:
    - text: |-
        ----------------------------------------
        STIG Finding ID: {{ stig_id }}
             The OS must require authentication
             to access single-user mode
        ----------------------------------------

{%- if stig_id in skipIt %}
notify_{{ stig_id }}-skipSet:
  test.show_notification:
    - text: |
        Handler for {{ stig_id }} has been selected for skip.
{%- else %}
  {%- for cfgFile in cfgFiles -%}
Require Authentication for Single User Mode ({{ cfgFile }}):
  file.replace:
    - name:  '{{ cfgFile }}'
    - pattern: '(^ExecStart=)(.*$)'
    - repl: '\g<1>-{{ fixString }}'
    - onchanges_in:
      - module: 'Reload systemctl daemon ({{ stig_id }})'
  {%- endfor %}

Reload systemctl daemon ({{ stig_id }}):
  module.run:
    - name: service.systemctl_reload

Restart Rescue Service ({{ stig_id }}):
  service.running:
    - name: 'rescue'
    - enable: true
    - reload: false
    - watch:
      - module: 'Reload systemctl daemon ({{ stig_id }})'

{%- endif %}
