# Finding ID:	RHEL-07-040590
# Version:	RHEL-07-040590_rule
# SRG ID:	SRG-OS-000074-GPOS-00042
# Finding Level:	high
#
# Rule Summary:
#	The SSH daemon must be configured to only use the SSHv2 protocol.
#
# CCI-000197
# CCI-000366
#    NIST SP 800-53 :: IA-5 (1) (c)
#    NIST SP 800-53A :: IA-5 (1).1 (v)
#    NIST SP 800-53 Revision 4 :: IA-5 (1) (c)
#    NIST SP 800-53 :: CM-6 b
#    NIST SP 800-53A :: CM-6.1 (iv)
#    NIST SP 800-53 Revision 4 :: CM-6 b
#
#################################################################
{%- set stig_id = 'RHEL-07-040590' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat1/files' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}
{%- set svcName = 'sshd' %}
{%- set sshConfigFile = '/etc/ssh/sshd_config' %}
{%- set sshParm = 'Protocol' %}

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
  {%- if salt.file.search(sshConfigFile, '^' + sshParm + ' .*') %}
    {%- if salt.file.search(sshConfigFile, '^' + sshParm + ' 2$') %}
file_{{ stig_id }}:
  cmd.run:
    - name: 'printf "\nchanged=no comment=''Protocol-version already set in {{ sshConfigFile }}''\n"'
    - cwd: /root
    - stateful: True
      {%- set runtype = 'cmd' %}
    {%- else %}
file_{{ stig_id }}:
  file.replace:
    - name: '{{ sshConfigFile }}'
    - pattern: "^{{ sshParm }} .*"
    - repl: "{{ sshParm }} 2"
      {%- set runtype = 'file' %}
    {%- endif %}
  {%- else %}
file_{{ stig_id }}:
  file.append:
    - name: '{{ sshConfigFile }}'
    - text: |-

        # SSH Must only allow version 2 (per STIG {{ stig_id }})
        {{ sshParm }} 2
    {%- set runtype = 'file' %}
  {%- endif %}
{%- endif %}

# Bleah: this is a mild botch. If above performs a 'cmd.run', this state
# will always cause a service restart event.
service_sshd:
  service.running:
    - name: '{{ svcName }}'
    - watch:
      - {{ runtype }}: file_{{ stig_id }}
