# Ref Doc:    STIG - RHEL 8 v1r7
# Finding ID: V-230287
# Rule ID:    SV-230287r743951_rule
# STIG ID:    RHEL-08-010490
# SRG ID:     SRG-OS-000480-GPOS-00227
#
# Finding Level: medium
#
# Rule Summary:
#       The SSH private host key files must have mode 0600 or
#       less permissive
#
# References:
#   CCI:
#     - CCI-001233
#   NIST SP 800-53 :: SI-2 (2)
#   NIST SP 800-53A :: SI-2 (2).1 (ii)
#   NIST SP 800-53 Revision 4 :: SI-2 (2)
#
#################################################################
{%- set stig_id = 'RHEL-08-010490' %}
{%- set helperLoc = 'ash-linux/el8/STIGbyID/cat2/files' %}

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
