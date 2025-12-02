# Ref Doc:
#   - STIG - RHEL 9 v2r5
#   - STIG - OEL  9 v1r2
#   - STIG - Alma 9 v1r3
# Finding ID:
#   - RHEL: V-257816
#   - OEL:  V-271727
#   - Alma: V-269284
# Rule ID:
#   - RHEL: SV-257816r1106435_rule
#   - OEL:  SV-271727r1091893_rule
#   - Alma: SV-269284r1101813_rule
# STIG ID:
#   - RHEL: RHEL-09-213105
#   - OEL:  OL09-00-002370
#   - Alma: ALMA-09-023010
# SRG ID:     SRG-OS-000480-GPOS-00227
#
# Finding Level: medium
#
# Rule Summary:
#       The OS must disable the use of user namespaces
#
# References:
#   - CCI:
#     - CCI-000366
#   - NIST:
#     -  SP 800-53 :: CM-6 b
#     -  SP 800-53A :: CM-6.1 (iv)
#     -  SP 800-53 Revision 4 :: CM-6 b
#
###########################################################################
{%- set stigIdByVendor = {
    'AlmaLinux': 'ALMA-09-023010',
    'CentOS Stream': 'RHEL-09-213105',
    'OEL': 'OL09-00-002370',
    'RedHat': 'RHEL-09-213105',
    'Rocky': 'RHEL-09-213105',
} %}
{%- set stig_id = stigIdByVendor[salt.grains.get('os')] %}
{%- set helperLoc = tpldir ~ '/files' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}
{%- set searchDirs =[
  '/etc/sysctl.d/',
  '/lib/sysctl.d/',
  '/run/sysctl.d',
  '/usr/lib/sysctl.d',
  '/usr/local/lib/sysctl.d',
] %}
{%- set newSysctlFile = '/etc/sysctl.d/99-max-user-namespace.conf' %}
{%- set sysctlFiles = [] %}
{%- for searchDir in searchDirs %}
  {%- do sysctlFiles.extend(
      salt.file.find(
        searchDir,
        type='f',
        name='*.conf',
        grep='user\.max_user_namespaces'
      )
    )
   %}
{%- endfor %}

{{ stig_id }}-description:
  test.show_notification:
    - text: |
        --------------------------------------
        STIG Finding ID: {{ stig_id }}
             The OS must disable the use of
             user namespaces
        --------------------------------------

{%- if stig_id in skipIt %}
notify_{{ stig_id }}-skipSet:
  test.show_notification:
    - text: |
        Handler for {{ stig_id }} has been selected for skip.
{%- else %}
  {%- for sysctlFile in sysctlFiles %}
Fix user.max_user_namespaces in {{ sysctlFile }}:
  file.replace:
    - name: '{{ sysctlFile }}'
    - pattern: '^(\s*|#(\s*|))(user\.max_user_namespaces)(\s*=\s*).*$'
    - repl: '\3 = 0'
    - watch_in:
      - service: 'Re-read kernel module-config files (max_user_namespaces)'
  {%- else %}
Ensure syctemctl settings-file exists:
  file.managed:
    - name: '{{ newSysctlFile }}'
    - create: True
    - group: 'root'
    - mode: '0644'
    - replace: False
    - selinux:
        serange: 's0'
        serole: 'object_r'
        setype: 'system_conf_t'
        seuser: 'system_u'
    - user: 'root'

Add user.max_user_namespaces in {{ newSysctlFile }}:
  file.append:
    - name: '{{ newSysctlFile }}'
    - text: 'user.max_user_namespaces = 0'
    - watch:
      - file: 'Ensure syctemctl settings-file exists'
    - watch_in:
      - service: 'Re-read kernel module-config files (max_user_namespaces)'
  {%- endfor %}
{%- endif %}

Re-read kernel module-config files (max_user_namespaces):
  service.running:
    - name: systemd-modules-load
    - enable: true
    - reload: false

