# Ref Doc:
#   - STIG - RHEL 9 v2r5      (02 Jul 2025)
#   - STIG - OEL 9 v1r2       (02 Jul 2025)
#   - STIG - AlmaLinux 9 v1r3 (02 Jul 2025)
# Finding ID:
#   - RHEL: V-258034
#   - OEL:  V-271450
#   - Alma: V-269357
# Rule ID:
#   - RHEL: SV-258034r1051267_rule
#   - OEL:  SV-271450r1092466_rule
#   - Alma: SV-269357r1050240_rule
# STIG ID:
#   - RHEL-09-291010
#   - OL09-00-000047
#   - ALMA-09-031370
# SRG ID:     SRG-OS-000114-GPOS-00059
#
# Finding Level: medium
#
# Rule Summary:
#       The OS must be configured to disable USB mass storage
#
# References:
#   CCI:
#     - CCI-000213
#   NIST:
#     - SP 800-53 ::
#     - SP 800-53A ::
#     - SP 800-53 Revision 4 ::
#
###########################################################################
{%- set stigIdByVendor = {
    'AlmaLinux': 'ALMA-09-031370',
    'CentOS Stream': 'RHEL-09-291010',
    'OEL': 'OL09-00-000047',
    'RedHat': 'RHEL-09-291010',
    'Rocky': 'RHEL-09-291010',
} %}
{%- set stig_id = stigIdByVendor[salt.grains.get('os')] %}
{%- set helperLoc = tpldir ~ '/files' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}
{%- set searchDir = '/etc/modprobe.d/' %}
{%- set modprobeFiles = [] %}
{%- if salt.file.file_exists('/etc/modprobe.conf') %}
  {%- do modprobeFiles.extends('/etc/modprobe.conf') %}
{%- endif %}
{%- set modprobeFiles = modprobeFiles + salt.file.find(
    searchDir,
    type='f',
    name='*.conf',
    grep='usb-storage'
  )
%}
{% set usbStorageFile = '/etc/modprobe.d/usb-storage.conf' %}

{{ stig_id }}-description:
  test.show_notification:
    - text: |-
        ----------------------------------------
        STIG Finding ID: {{ stig_id }}
            The OS must be configured to disable
            USB mass storage
        ----------------------------------------

{%- if stig_id in skipIt %}
notify_{{ stig_id }}-skipSet:
  test.show_notification:
    - text: |
        Handler for {{ stig_id }} has been selected for skip.
{%- else %}
  {%- for modprobeFile in modprobeFiles %}
Disable USB Mass Storage Support - install as false ({{ modprobeFile }}):
  file.replace:
    - name: '{{ modprobeFile }}'
    - append_if_not_found: True
    - not_found_content: |
        # Set per rule {{ stig_id }}
        install usb-storage /bin/false
    - watch_in:
      - service: 'Re-read kernel module-config files (USB Mass Storage)'
    - pattern: '(^(|\s\s*))install\s\s*usb-storage\s\s*.*'
    - repl: 'install usb-storage /bin/false'

Disable USB Mass Storage Support - blacklist ({{ modprobeFile }}):
  file.replace:
    - name: '{{ modprobeFile }}'
    - append_if_not_found: True
    - not_found_content: |
        # Set per rule {{ stig_id }}
        blacklist usb-storage
    - watch_in:
      - service: 'Re-read kernel module-config files (USB Mass Storage)'
    - pattern: '(^(|\s\s*))blacklist\s\s*usb-storage'
    - repl: 'blacklist usb-storage'
  {%- else %}
Disable USB Mass Storage Support - create-file ({{ usbStorageFile }}):
  file.managed:
    - name: '{{ usbStorageFile }}'
    - contents: |
        # Installed per STIG-ID '{{ stig_id }}'
        install usb-storage /bin/false
        blacklist usb-storage
    - group: 'root'
    - mode: '0600'
    - watch_in:
      - service: 'Re-read kernel module-config files (USB Mass Storage)'
    - selinux:
        serange: 's0'
        serole: 'object_r'
        setype: 'modules_conf_t'
        seuser: 'system_u'
    - user: 'root'
  {%- endfor %}
{%- endif %}

Re-read kernel module-config files (USB Mass Storage):
  service.running:
    - name: systemd-modules-load
    - enable: true
    - reload: false
