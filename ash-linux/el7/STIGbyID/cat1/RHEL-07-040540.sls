# Finding ID:	RHEL-07-040540
# Version:	RHEL-07-040540_rule
# SRG ID:	SRG-OS-000480-GPOS-00227
# Finding Level:	high
#
# Rule Summary:
#	Remote X connections for interactive users must be encrypted.
#
# CCI-000366
#    NIST SP 800-53 :: CM-6 b
#    NIST SP 800-53A :: CM-6.1 (iv)
#    NIST SP 800-53 Revision 4 :: CM-6 b
#
#################################################################
{%- set stig_id = 'RHEL-07-040540' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat1/files' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}
{%- set svcName = 'sshd' %}
{%- set baseXpkg = 'xorg-x11-server-Xorg' %}
{%- set sshConfigFile = '/etc/ssh/sshd_config' %}
{%- set sshParm = 'X11Forwarding' %}

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
    {%- if salt.file.search(sshConfigFile, '^' + sshParm + ' yes') %}
file_{{ stig_id }}:
  cmd.run:
    - name: 'printf "\nchanged=no comment=''X11-encryption already set in {{ sshConfigFile }}.''\n"'
    - cwd: /root
    - stateful: True
      {%- set runtype = 'cmd' %}
    {%- else %}
file_{{ stig_id }}:
  file.replace:
    - name: '{{ sshConfigFile }}'
    - pattern: "^{{ sshParm }} .*"
    - repl: "{{ sshParm }} yes"
      {%- set runtype = 'file' %}
    {%- endif %}
  {%- else %}
file_{{ stig_id }}:
  file.append:
    - name: '{{ sshConfigFile }}'
    - text: |-

        # SSH Must not allow empty passwords (per STIG {{ stig_id }})
        {{ sshParm }} yes
    {%- set runtype = 'file' %}
  {%- endif %}

# Bleah: this is a mild botch. If above performs a 'cmd.run', this state
# will always cause a service restart event.
service_{{ stig_id }}-sshd:
  service.running:
    - name: '{{ svcName }}'
    - watch:
      - {{ runtype }}: file_{{ stig_id }}

  {%- if not salt.pkg.version(baseXpkg) %}
cmd_{{ stig_id }}-notify:
  cmd.run:
    - name: 'printf "\nchanged=no comment=''Note: X-related subsystems not installed.''\n"'
    - cwd: /root
    - stateful: True
    - cwd: /root
  {%- endif %}
{%- endif %}
