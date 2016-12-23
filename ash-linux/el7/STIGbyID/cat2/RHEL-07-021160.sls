# Finding ID:	RHEL-07-021160
# Version:	RHEL-07-021160_rule
# SRG ID:	SRG-OS-000480-GPOS-00227
# Finding Level:	medium
# 
# Rule Summary:
#	Cron logging must be implemented.
#
# CCI-000366 
#    NIST SP 800-53 :: CM-6 b 
#    NIST SP 800-53A :: CM-6.1 (iv) 
#    NIST SP 800-53 Revision 4 :: CM-6 b 
#
#################################################################
{%- set stig_id = 'RHEL-07-021160' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat2/files' %}
{%- set checkFile = '/etc/rsyslog.conf' %}
{%- set srchPatrn = '^\*.\* ~' %}
{%- set replPatrn = 'cron.* /var/log/cron.log' %}

script_{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stig_id }}.sh
    - cwd: /root

{%- if salt.pkg.version('rsyslog') %}
  {%- if salt.file.search(checkFile, srchPatrn) %}
setconf_{{ stig_id }}-{{ checkFile }}:
  file.replace:
    - name: '{{ checkFile }}'
    - pattern: '^(?P<srctok>{{ srchPatrn }})'
    - repl: '{{ replPatrn }}\n\g<srctok>'
  {%- else %}
setconf_{{ stig_id }}-{{ checkFile }}:
  file.append:
    - name: '{{ checkFile }}'
    - text: '{{ replPatrn }}'
  {%- endif %}
{%- else %}
notify_{{ stig_id }}-notPresent:
  cmd.run:
    - name: 'printf "\nchanged=no comment=''The rsyslog service is not present.''\n"'
    - cwd: /root
    - stateful: True
{%- endif %}
