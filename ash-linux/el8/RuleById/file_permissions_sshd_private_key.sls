# Versions:
#   - file_permissions_sshd_private_key
# SRG ID:
#   - SRG-OS-000480-GPOS-00227
# Finding Level:        medium
#
# Rule Summary:
#       All SSH private host-key files must be set to mode '0600'
#
# Identifiers:
#
# References:
#   - CCI-000366
#   - CIP-003-8 R5.1.1
#   - CIP-003-8 R5.3
#   - CIP-004-6 R2.3
#   - CIP-007-3 R2.1
#   - CIP-007-3 R2.2
#   - CIP-007-3 R2.3
#   - CIP-007-3 R5.1
#   - CIP-007-3 R5.1.1
#   - CIP-007-3 R5.1.2
#   - AC-17(a)
#   - CM-6(a)
#   - AC-6(1)
#   - SV-248602r779372_rule
#
#################################################################
{%- set stig_id = 'file_permissions_sshd_private_key' %}
{%- set helperLoc = 'ash-linux/el8/RuleById/files' %}

# Log a description of what we're setting
script_{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stig_id }}.sh
    - cwd: /root

# Find and iterated all SSH private host-key files
{%- for host_ssh_key_files in salt.file.find('/etc/ssh', type='f', name='*_key') %}
{%- set filename = salt.file.basename(host_ssh_key_files) %}
ssh_key_perm_{{ filename }}:
  file.managed:
    - group: root
    - mode: '0600'
    - name: '{{ host_ssh_key_files }}'
    - selinux:
        serange: 's0'
        serole: 'object_r'
        setype: 'sshd_key_t'
        seuser: 'system_u'
    - user: root
{%- endfor %}
