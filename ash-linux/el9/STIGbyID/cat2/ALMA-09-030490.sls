# Ref Doc:
#   - STIG - AlmaLinux 9 v1r3 (02 Jul 2025)
# Finding ID:
#   - Alma: V-269349
# Rule ID:
#   - Alma: SV-269349r1050232_rule
# STIG ID:
#   - ALMA-09-030490
# SRG ID:   SRG-OS-000095-GPOS-00049
#
# Finding Level: medium
#
# Rule Summary:
#       Cameras must be disabled or covered when not in use
#
# References:
#   CCI:
#     - CCI-000381
#   NIST:
#     - SP 800-53 :: CM-7
#     - SP 800-53A :: CM-7.1 (ii)
#     - SP 800-53 Revision 4 :: CM-7 a
#
###########################################################################
{%- set stigIdByVendor = {
    'AlmaLinux': 'ALMA-09-030490',
    'CentOS Stream': 'ALMA-09-030490',
    'OEL': 'ALMA-09-030490',
    'RedHat': 'ALMA-09-030490',
    'Rocky': 'ALMA-09-030490',
} %}
{%- set stig_id = stigIdByVendor[salt.grains.get('os')] %}
{%- set osName = salt.grains.get('os') %}
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
    grep='udf'
  )
%}
{% set uvcvideoFile = '/etc/modprobe.d/uvcvideo.conf' %}

{{ stig_id }}-description:
  test.show_notification:
    - text: |-
        ----------------------------------------
        STIG Finding ID: {{ stig_id }}
             Cameras must be disabled or covered
             when not in use
        ----------------------------------------

{%- if stig_id in skipIt %}
notify_{{ stig_id }}-skipSet:
  test.show_notification:
    - text: |
        Handler for {{ stig_id }} has been selected for skip.
{%- elif osName == 'AlmaLinux' %}
  {%- for modprobeFile in modprobeFiles %}
Disable Video/Camera Support - install as false ({{ modprobeFile }}):
  file.replace:
    - name: '{{ modprobeFile }}'
    - append_if_not_found: True
    - not_found_content: |
        # Set per rule {{ stig_id }}
        install uvcvideo /bin/false
    - watch_in:
      - service: 'Re-read kernel module-config files (UVC Video)'
    - pattern: '(^(|\s\s*))install\s\s*uvcvideo\s\s*.*'
    - repl: 'install uvcvideo /bin/false'

Disable Video/Camera Support - blacklist ({{ modprobeFile }}):
  file.replace:
    - name: '{{ modprobeFile }}'
    - append_if_not_found: True
    - not_found_content: |
        # Set per rule {{ stig_id }}
        blacklist uvcvideo
    - watch_in:
      - service: 'Re-read kernel module-config files (UVC Video)'
    - pattern: '(^(|\s\s*))blacklist\s\s*uvcvideo'
    - repl: 'blacklist uvcvideo'
  {%- else %}
Disable Video/Camera Support - create-file ({{ uvcvideoFile }}):
  file.managed:
    - name: '{{ uvcvideoFile }}'
    - contents: |
        # Installed per STIG-ID '{{ stig_id }}'
        install uvcvideo /bin/false
        blacklist uvcvideo
    - group: 'root'
    - mode: '0600'
    - watch_in:
      - service: 'Re-read kernel module-config files (UVC Video)'
    - selinux:
        serange: 's0'
        serole: 'object_r'
        setype: 'modules_conf_t'
        seuser: 'system_u'
    - user: 'root'
  {%- endfor %}
{%- else %}
Skip Reason ({{ stig_id }}):
  test.show_notification:
    - text: |-
        ----------------------------------------
        STIG Finding ID: {{ stig_id }}
             Not valid for distro '{{ osName }}'
        ----------------------------------------
    - watch_in:
      - service: 'Re-read kernel module-config files (UVC Video)'
{%- endif %}

Re-read kernel module-config files (UVC Video):
  service.running:
    - name: systemd-modules-load
    - enable: true
    - reload: false
