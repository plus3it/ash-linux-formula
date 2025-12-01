# Ref Doc:     STIG - AlmaLinux 9 v1r3 (02 Jul 2025)
# Finding ID:  V-269348
# Rule ID:    SV-269348r1050230_rule
# STIG ID:     ALMA-09-030380
# SRG ID:      SRG-OS-000095-GPOS-00049
#
# Finding Level: medium
#
# Rule Summary:
#       The OS must must disable mounting of udf filesystems
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
    'AlmaLinux': 'ALMA-09-030380',
    'CentOS Stream': 'ALMA-09-030380',
    'OEL': 'ALMA-09-030380',
    'RedHat': 'ALMA-09-030380',
    'Rocky': 'ALMA-09-030380',
} %}
{%- set osName = salt.grains.get('os') %}
{%- set stig_id = stigIdByVendor[osName] %}
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
{% set udfFile = '/etc/modprobe.d/udf.conf' %}


{{ stig_id }}-description:
  test.show_notification:
    - text: |-
        ----------------------------------------
        STIG Finding ID: {{ stig_id }}
             The OS must must disable mounting
             of UDF-based filesystems
        ----------------------------------------

{%- if stig_id in skipIt %}
notify_{{ stig_id }}-skipSet:
  test.show_notification:
    - text: |
        Handler for {{ stig_id }} has been selected for skip.
{%- elif osName == 'AlmaLinux' %}
  {%- for modprobeFile in modprobeFiles if modprobeFiles %}
Disable UDF Filesystem Support - install as false ({{ modprobeFile }}):
  file.replace:
    - name: '{{ modprobeFile }}'
    - append_if_not_found: True
    - not_found_content: |
        # Set per rule {{ stig_id }}
        install udf /bin/false
    - watch_in:
      - service: 'Re-read kernel module-config files (UDF)'
    - pattern: '(^(|\s\s*))install\s\s*udf\s\s*.*'
    - repl: 'install udf /bin/false'

Disable UDF Filesystem Support - blacklist ({{ modprobeFile }}):
  file.replace:
    - name: '{{ modprobeFile }}'
    - append_if_not_found: True
    - not_found_content: |
        # Set per rule {{ stig_id }}
        blacklist udf
    - watch_in:
      - service: 'Re-read kernel module-config files (UDF)'
    - pattern: '(^(|\s\s*))blacklist\s\s*udf'
    - repl: 'blacklist udf'
  {%- else %}
Disable UDF Filesystem Support - create-file ({{ udfFile }}):
  file.managed:
    - name: '{{ udfFile }}'
    - contents: |
        # Installed per STIG-ID '{{ stig_id }}'
        install udf /bin/false
        blacklist udf
    - group: 'root'
    - mode: '0600'
    - watch_in:
      - service: 'Re-read kernel module-config files (UDF)'
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
      - service: 'Re-read kernel module-config files (UDF)'
{%- endif %}

Re-read kernel module-config files (UDF):
  service.running:
    - name: systemd-modules-load
    - enable: true
    - reload: false
