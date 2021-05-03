# Finding ID:	RHEL-07-020220
# Version:	RHEL-07-020220_rule
# SRG ID:	SRG-OS-000480-GPOS-00227
# Finding Level:	high
#
# Rule Summary:
#	The x86 Ctrl-Alt-Delete key sequence must be disabled.
#
# CCI-000366
#    NIST SP 800-53 :: CM-6 b
#    NIST SP 800-53A :: CM-6.1 (iv)
#    NIST SP 800-53 Revision 4 :: CM-6 b
#
#################################################################
{%- set stig_id = 'RHEL-07-020220' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat1/files' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}
{%- set svcName = 'ctrl-alt-del.target' %}

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
stop_{{ stig_id }}-{{ svcName }}:
  service.dead:
    - name: '{{ svcName }}'
    - enable: False

mask_{{ stig_id }}-{{ svcName }}:
  cmd.run:
    - name: 'systemctl mask {{ svcName }}'
    - cwd: /root
{%- endif %}
