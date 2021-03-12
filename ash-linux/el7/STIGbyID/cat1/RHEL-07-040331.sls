# Finding ID:	RHEL-07-040331
# Version:	RHEL-07-040331_rule
# SRG ID:	SRG-OS-000480-GPOS-00227
# Finding Level:	high
#
# Rule Summary:
#	There must be no shosts.equiv files on the system.
#
# CCI-000366
#    NIST SP 800-53 :: CM-6 b
#    NIST SP 800-53A :: CM-6.1 (iv)
#    NIST SP 800-53 Revision 4 :: CM-6 b
#
#################################################################
{%- set stig_id = 'RHEL-07-040331' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat1/files' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}
{%- set hostsEquiv = '/etc/ssh/shosts.equiv' %}
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
  {%- if salt.file.file_exists(hostsEquiv) %}
file_{{ stig_id }}-hostsEquiv:
  file.absent:
    - name: {{ hostsEquiv }}
  {%- else %}
file_{{ stig_id }}-hostsEquiv:
  cmd.run:
    - name: 'printf "\nchanged=no comment=''No offending ''{{ hostsEquiv }}'' file found.''\n"'
    - cwd: /root
    - stateful: True
  {%- endif %}
{%- endif %}
