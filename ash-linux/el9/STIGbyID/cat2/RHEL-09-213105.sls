# Ref Doc:    STIG - RHEL 9 v2r4
# Finding ID: V-257816
# Rule ID:    content_rule_sysctl_user_max_user_namespaces_no_remediation_rule
# STIG ID:    RHEL-09-213105
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
{%- set stig_id = 'RHEL-09-213105' %}
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

{{ stig_id }}-description:
  test.show_notification:
    - text: |
        --------------------------------------
        STIG Finding ID: V-257816
             The OS must disable the use of
             user namespaces
        --------------------------------------

{%- if stig_id in skipIt %}
notify_{{ stig_id }}-skipSet:
  test.show_notification:
    - text: |
        Handler for {{ stig_id }} has been selected for skip.
{%- else %}
  {%- for searchDir in searchDirs %}
    {%- do sysctlFiles.extend(salt.file.find(searchDir, type='f', name='*.conf', grep='user\.max_user_namespaces')) %}
  {%- endfor %}
  {% if sysctlFiles|length == 0 %}
Ensure syctemctl settings-file exists:
  file.managed:
    - name: '{{ newSysctlFile }}'
    - create: True
    - group: 'root'
    - mode: '0644'
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
  {%- else %}
    {%- for sysctlFile in sysctlFiles %}
Fix user.max_user_namespaces in {{ sysctlFile }}:
  file.replace:
    - name: '{{ sysctlFile }}'
    - pattern: '^(\s*|#(\s*|))(user\.max_user_namespaces)(\s*=\s*).*$'
    - repl: '\3 = 0'
    {%- endfor %}
  {%- endif %}
{%- endif %}
