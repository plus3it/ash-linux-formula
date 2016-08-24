# Finding ID:	RHEL-07-010440
# Version:	RHEL-07-010440_rule
# SRG ID:	SRG-OS-000480-GPOS-00229
# Finding Level:	high
#
# Rule Summary:
#	The operating system must not allow empty passwords for SSH
#	logon to the system.
#
# CCI-000366
#    NIST SP 800-53 :: CM-6 b
#    NIST SP 800-53A :: CM-6.1 (iv)
#    NIST SP 800-53 Revision 4 :: CM-6 b
#
#################################################################
{%- set stig_id = 'RHEL-07-010440' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat1/files' %}
{%- set sshConfigFile = '/etc/ssh/sshd_config' %}

script_{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stig_id }}.sh
    - cwd: /root

{%- if salt['file.search'](sshConfigFile, '^PermitEmptyPasswords .*') %}
  {%- if salt['file.search'](sshConfigFile, '^PermitEmptyPasswords no') %}
file_{{ stig_id }}:
  cmd.run:
    - name: 'echo "Empty passwords already disabled in ''{{ sshConfigFile }}''"'
    {%- set runtype = 'cmd' %}
  {%- else %}
file_{{ stig_id }}:
  file.replace:
    - name: '{{ sshConfigFile }}'
    - pattern: "^PermitEmptyPasswords .*"
    - repl: "PermitEmptyPasswords no"
    {%- set runtype = 'file' %}
  {%- endif %}
{%- else %}
file_{{ stig_id }}:
  file.append:
    - name: '{{ sshConfigFile }}'
    - text:
      - ' '    
      - '# SSH Must not allow empty passwords (per STIG {{ stig_id }})'
      - 'PermitEmptyPasswords no'
  {%- set runtype = 'file' %}
{%- endif %}

# Bleah: this is a mild botch. If above performs a 'cmd.run', this state
# will always cause a service restart event.
service_sshd:
  service.running:
    - name: 'sshd'
    - watch:
      - {{ runtype }}: file_{{ stig_id }}
