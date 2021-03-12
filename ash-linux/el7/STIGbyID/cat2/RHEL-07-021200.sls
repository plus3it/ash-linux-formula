# Finding ID:	RHEL-07-021200
# Version:	RHEL-07-021200_rule
# SRG ID:	SRG-OS-000480-GPOS-00227
# Finding Level:	medium
#
# Rule Summary:
#	If the cron.allow file exists it must be group-owned by root.
#
# CCI-000366
#    NIST SP 800-53 :: CM-6 b
#    NIST SP 800-53A :: CM-6.1 (iv)
#    NIST SP 800-53 Revision 4 :: CM-6 b
#
#################################################################
{%- set stig_id = 'RHEL-07-021200' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat2/files' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}
{%- set allowFile = '/etc/cron.allow' %}

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
  {%- if salt.file.file_exists(allowFile) %}
fixown_{{ stig_id }}-{{ allowFile }}:
  file.managed:
    - name: '{{ allowFile }}'
    - group: 'root'
  {%- else %}
fixown_{{ stig_id }}-{{ allowFile }}:
  cmd.run:
    - name: 'printf "\nchanged=no comment=''File {{ allowFile }} not present.''\n"'
    - cwd: /root
    - stateful: True
  {%- endif %}
{%- endif %}
