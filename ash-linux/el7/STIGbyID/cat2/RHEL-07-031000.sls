# Finding ID:	RHEL-07-031000
# Version:	RHEL-07-031000_rule
# SRG ID:	SRG-OS-000480-GPOS-00227
# Finding Level:	medium
#
# Rule Summary:
#	The system must send rsyslog output to a log aggregation server.
#
# CCI-000366
#    NIST SP 800-53 :: CM-6 b
#    NIST SP 800-53A :: CM-6.1 (iv)
#    NIST SP 800-53 Revision 4 :: CM-6 b
#
#################################################################
{%- set stig_id = 'RHEL-07-031000' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat2/files' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}
{%- set alrthost = salt.pillar.get('ash-linux:lookup:rsyslog:destination', 'localhost') %}
{%- set alrtport = salt.pillar.get('ash-linux:lookup:rsyslog:log_port', '514') %}
{%- set checkFile = '/etc/rsyslog.conf' %}

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
  {%- if salt.pkg.version('rsyslog') %}
setconf_{{ stig_id }}-{{ checkFile }}:
  file.replace:
    - name: '{{ checkFile }}'
    - pattern: '^\*.\* @@.*'
    - repl: '*.* @@{{ alrthost }}:{{ alrtport }}'
    - append_if_not_found: True
  {%- else %}
notify_{{ stig_id }}-notPresent:
  cmd.run:
    - name: 'printf "\nchanged=no comment=''The rsyslog service is not present.''\n"'
    - cwd: /root
    - stateful: True
  {%- endif %}
{%- endif %}
