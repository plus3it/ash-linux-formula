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
#   - RHEL-09-213065
#   - OL09-00-000044
#   - ALMA-09-030270
# SRG ID:   SRG-OS-000095-GPOS-00049
#
# Finding Level: medium
#
# Rule Summary:
#       The OS must disable the Transparent Inter Process Communication (TIPC)
#       kernel module.
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
    'AlmaLinux': 'ALMA-09-030270',
    'CentOS Stream': 'RHEL-09-213065',
    'OEL': 'OL09-00-000044',
    'RedHat': 'RHEL-09-213065',
    'Rocky': 'RHEL-09-213065',
} %}
{%- set stig_id = stigIdByVendor[salt.grains.get('os')] %}
{%- set helperLoc = tpldir ~ '/files' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}
{%- set searchDir = '/etc/modprobe.d/' %}
{%- set modprobeFiles = [] %}
{%- if salt.file.directory_exists('/etc/modprobe.conf') %}
  {%- do modprobeFiles.extends('/etc/modprobe.conf') %}
{%- endif %}
{%- set modprobeFiles = modprobeFiles + salt.file.find(
    searchDir,
    type='f',
    name='*.conf',
    grep='tipc'
  )
%}
{% set tipcFile = '/etc/modprobe.d/tipc.conf'%}


{{ stig_id }}-description:
  test.show_notification:
    - text: |-
        ----------------------------------------
        STIG Finding ID: {{ stig_id }}
             The OS must must disable the TIPC
             kernel module.
        ----------------------------------------

{%- if stig_id in skipIt %}
notify_{{ stig_id }}-skipSet:
  test.show_notification:
    - text: |
        Handler for {{ stig_id }} has been selected for skip.
{%- else %}
  {%- if modprobeFiles %}
    {%- for modprobeFile in modprobeFiles %}
Disable TIPC kernel module - install as false ({{ modprobeFile }}):
  file.replace:
    - name: '{{ modprobeFile }}'
    - append_if_not_found: True
    - not_found_content: |
        # Set per rule {{ stig_id }}
        install tipc /bin/false
    - onchanges_in:
      - service: 'Re-read kernel module-config files (TIPC)'
    - pattern: '(^(|\s\s*))install\s\s*tipc\s\s*.*'
    - repl: 'install tipc /bin/false'

Disable TIPC kernel module - blacklist ({{ modprobeFile }}):
  file.replace:
    - name: '{{ modprobeFile }}'
    - append_if_not_found: True
    - not_found_content: |
        # Set per rule {{ stig_id }}
        blacklist tipc
    - onchanges_in:
      - service: 'Re-read kernel module-config files (TIPC)'
    - pattern: '(^(|\s\s*))blacklist\s\s*tipc'
    - repl: 'blacklist tipc'
    {%- endfor %}
  {%- else %}
Disable TIPC kernel module - create-file ({{ tipcFile }}):
  file.managed:
    - name: '{{ tipcFile }}'
    - contents: |
        install tipc /bin/false
        blacklist tipc
    - group: 'root'
    - mode: '0600'
    - onchanges_in:
      - service: 'Re-read kernel module-config files (TIPC)'
    - selinux:
        serange: 's0'
        serole: 'object_r'
        setype: 'modules_conf_t'
        seuser: 'system_u'
    - user: 'root'
  {%- endif %}
{%- endif %}

Re-read kernel module-config files (TIPC):
  service.running:
    - name: systemd-modules-load
    - enable: true
    - reload: true
