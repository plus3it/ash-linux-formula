# Finding ID:	RHEL-07-040250
# Version:	RHEL-07-040250_rule
# SRG ID:	SRG-OS-000420-GPOS-00186
# Finding Level:	medium
#
# Rule Summary:
#	The operating system must protect against or limit the effects
#	of Denial of Service (DoS) attacks by validating the operating
#	system is implementing rate-limiting measures on impacted
#	network interfaces.
#
# CCI-002385
#    NIST SP 800-53 Revision 4 :: SC-5
#
#################################################################
{%- set stig_id = 'RHEL-07-040250' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat2/files' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}
{%- set fwRule = salt['cmd.shell']('firewall-cmd --direct --get-rule ipv4 filter IN_public_allow') %}

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
  {%- if ( '--limit' in fwRule.split(' ') )
   and ( '--limit-burst' in fwRule.split(' ') )
 %}
cmd_{{ stig_id }}-firewall:
  cmd.run:
    - name: 'printf "Found rule:\n\t{{ fwRule }}"'
    - cwd: /root
  {%- else %}
cmd_{{ stig_id }}-firewall:
  cmd.run:
    - name: 'firewall-cmd --direct --add-rule ipv4 filter IN_public_allow 0 -m tcp -p tcp -m limit --limit 25/minute --limit-burst 100 -j ACCEPT'
    - cwd: /root

save_{{ stig_id }}-firewall:
  module.run:
    - name: 'firewalld.make_permanent'
    - require:
      - cmd: 'cmd_{{ stig_id }}-firewall'
  {%- endif %}
{%- endif %}
