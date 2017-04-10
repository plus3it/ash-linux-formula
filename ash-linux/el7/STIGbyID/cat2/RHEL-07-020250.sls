# Finding ID:	RHEL-07-020250
# Version:	RHEL-07-020250_rule
# SRG ID:	SRG-OS-000480-GPOS-00227
# Finding Level:	medium
# 
# Rule Summary:
#	System security patches and updates must be installed and up to date.
#
# CCI-000366 
#    NIST SP 800-53 :: CM-6 b 
#    NIST SP 800-53A :: CM-6.1 (iv) 
#    NIST SP 800-53 Revision 4 :: CM-6 b 
#
#################################################################
{%- set stig_id = 'RHEL-07-020250' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat2/files' %}
{%- set maxDays = salt.pillar.get('ash-linux:lookup:mustpatch-days', 30) %}
{%- set daysToSec = maxDays * 24 * 60 * 60 %}
{%- set todaysdt = salt['cmd.shell']('date "+%s"') %}
{%- set lastUpdt = salt['cmd.shell']("date -d $(yum history 2> /dev/null | awk -F '|' '$4 ~ / U/{print $3}' | head -1 | sed -e 's/^ *//' -e 's/ .*$//') +%s") %}
{%- set dateDiff = todaysdt|int - lastUpdt|int %}

script_{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stig_id }}.sh
    - cwd: /root

{%- if daysToSec >= todaysdt|int - lastUpdt|int %} 
notify_{{ stig_id }}-lastUpdate:
  cmd.run:
    - name: 'printf "\nchanged=no comment=''System updated less than {{ maxDays }} ago.''\n"'
    - cwd: /root
    - stateful: True
{%- else %}
notify_{{ stig_id }}-lastUpdate:
  cmd.run:
    - name: 'printf "\nchanged=no comment=''System last updated more than {{ maxDays }} ago: updating.''\n"'
    - cwd: /root
    - stateful: True

upgrade_{{ stig_id }}:
  pkg.uptodate:
    - require:
      - cmd: notify_{{ stig_id }}-lastUpdate
{%- endif %}
