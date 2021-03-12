# STIG ID:	RHEL-07-010470
# Rule ID:	SV-86583r3_rule
# Vuln ID:	V-71959
# SRG ID:	SRG-OS-000480-GPOS-00229
# Finding Level:	medium
#
# Rule Summary:
#	The operating system must not allow a non-certificate trusted
#	host SSH logon to the system.
#
# CCI-000366
#    NIST SP 800-53 :: CM-6 b
#    NIST SP 800-53A :: CM-6.1 (iv)
#    NIST SP 800-53 Revision 4 :: CM-6 b
#
#################################################################
{%- set stig_id = 'RHEL-07-010470' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat2/files' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}
{%- set svcName = 'sshd' %}
{%- set sshConfigFile = '/etc/ssh/sshd_config' %}
{%- set sshParm = 'HostbasedAuthentication' %}
{%- set sshPval = 'no' %}

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
    {%- if salt.file.search(sshConfigFile, '^' + sshParm + ' 2') %}
file_{{ stig_id }}:
  cmd.run:
    - name: 'printf "\nchanged=no comment=''{{ sshParm }} already set to {{ sshPval }}in ''{{ sshConfigFile }}.''\n"'
    - cwd: /root
    - stateful: True
      {%- set runtype = 'cmd' %}
    {%- else %}
file_{{ stig_id }}:
  file.replace:
    - name: '{{ sshConfigFile }}'
    - pattern: "^{{ sshParm }} .*"
    - repl: "{{ sshParm }} {{ sshPval }}"
      {%- set runtype = 'file' %}
    {%- endif %}
  {%- else %}
file_{{ stig_id }}:
  file.append:
    - name: '{{ sshConfigFile }}'
    - text:
      - ' '
      - '# SSH must not allow a non-certificate trusted host logon (per STIG {{ stig_id }})'
      - '{{ sshParm }} {{ sshPval }}'
    {%- set runtype = 'file' %}
  {%- endif %}
{%- endif %}

# Bleah: this is a mild botch. If above performs a 'cmd.run', this state
# will always cause a service restart event.
service_{{ stig_id }}-sshd:
  service.running:
    - name: '{{ svcName }}'
    - watch:
      - {{ runtype }}: file_{{ stig_id }}
