# STIG ID:	RHEL-07-010300
# Rule ID:	SV-86563r3_rule
# Vuln ID:	V-71939
# SRG ID:	SRG-OS-000106-GPOS-00053
# Finding Level:	high
# 
# Rule Summary:
#	The SSH daemon must not allow authentication using an empty password.
#
# CCI-000766 
#    NIST SP 800-53 :: IA-2 (2) 
#    NIST SP 800-53A :: IA-2 (2).1 
#    NIST SP 800-53 Revision 4 :: IA-2 (2) 
#
#################################################################
{%- set stig_id = 'RHEL-07-010300' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat1/files' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}
{%- set sshConfigFile = '/etc/ssh/sshd_config' %}

script_{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stig_id }}.sh
    - cwd: /root

{%- if stig_id in skipIt %}
notify_{{ stig_id }}-skipSet:
  cmd.run:
    - name: 'printf "\nchanged=no comment=''Handler for {{ stig_id }} has been selected for skip.''\n"'
    - stateful: True
    - cwd: /root
{%- else %}
  {%- if salt.file.search(sshConfigFile, '^PermitEmptyPasswords .*') %}
    {%- if salt.file.search(sshConfigFile, '^PermitEmptyPasswords no') %}
file_{{ stig_id }}:
  cmd.run:
    - name: 'printf "\nchanged=no comment=''Empty passwords already disabled in {{ sshConfigFile }}''.\n"'
    - cwd: /root
    - stateful: True
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
    - text: |-
        
        # SSH Must not allow empty passwords (per STIG {{ stig_id }})
        PermitEmptyPasswords no
    {%- set runtype = 'file' %}
  {%- endif %}

# Bleah: this is a mild botch. If above performs a 'cmd.run', this state
# will always cause a service restart event.
service_{{ stig_id }}-sshd:
  service.running:
    - name: 'sshd'
    - watch:
      - {{ runtype }}: file_{{ stig_id }}
{%- endif %}
