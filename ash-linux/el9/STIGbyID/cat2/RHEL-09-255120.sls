# Ref Doc:    STIG - RHEL 9 v2r5
# Finding ID:
#   - RHEL 9: V-258000
#   - OEL 9:  V-271771
#   - Alma 9: V-269265
# Rule ID:
#   - RHEL 9: SV-258000r1045063_rule
#   - OEL 9:  SV-271771r1092025_rule
#   - Alma 9: SV-269265r1050147_rule
# STIG ID:
#   - RHEL 9: RHEL-09-255120
#   - OEL 9:  OL09-00-002502
#   - Alma 9: ALMA-09-020920
# SRG ID:     SRG-OS-000480-GPOS-00227
#
# Finding Level: medium
#
# Rule Summary:
#       The SSH private host key files must have mode 0640 or
#       less permissive
#
# References:
#   CCI:
#     - CCI-001233
#   NIST:
#     -  SP 800-53 :: CM-6 b
#     -  SP 800-53A :: CM-6.1 (iv)
#     -  SP 800-53 Revision 4 :: CM-6 b
#
#################################################################
{%- set stigIdByVendor = {
    'AlmaLinux': 'ALMA-09-020920',
    'CentOS Stream': 'RHEL-09-255120',
    'OEL': 'OL09-00-002502',
    'RedHat': 'RHEL-09-255120',
    'Rocky': 'RHEL-09-255120',
} %}
{%- set stig_id = stigIdByVendor[salt.grains.get('os')] %}
{%- set helperLoc = tpldir ~ '/files' %}

{{ stig_id }}-description:
  test.show_notification:
    - text: |
        --------------------------------------------------
        STIG Finding ID: file_permissions_sshd_private_key
           All SSH private host-key files must be set to
           mode '0640' or less permissive
        --------------------------------------------------


# Find and iterated all SSH private host-key files
{%- for host_ssh_key_files in salt.file.find('/etc/ssh', type='f', name='*_key') %}
{%- set filename = salt.file.basename(host_ssh_key_files) %}
SSHD hostkey-permission - {{ filename }} ({{ stig_id }}):
  file.managed:
    - group: root
    - mode: '0640'
    - name: '{{ host_ssh_key_files }}'
    - selinux:
        serange: 's0'
        serole: 'object_r'
        setype: 'sshd_key_t'
        seuser: 'system_u'
    - user: root
{%- endfor %}
