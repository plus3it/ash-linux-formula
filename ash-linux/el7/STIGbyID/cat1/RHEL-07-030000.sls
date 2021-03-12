# STIG ID:	RHEL-07-030000
# Rule ID:	SV-86703r3_rule
# Vuln ID:	V-72079
# SRG ID:	SRG-OS-000038-GPOS-00016
# Finding Level:	high
#
# Rule Summary:
#	Auditing must be configured to produce records containing
#	information to establish what type of events occurred, where
#	the events occurred, the source of the events, and the
#	outcome of the events.These audit records must also identify
#	individual identities of group account users.
#
# CCI-000131
# CCI-000126
#    NIST SP 800-53 :: AU-3
#    NIST SP 800-53A :: AU-3.1
#    NIST SP 800-53 Revision 4 :: AU-3
#    NIST SP 800-53 :: AU-2 d
#    NIST SP 800-53A :: AU-2.1 (v)
#    NIST SP 800-53 Revision 4 :: AU-2 d
#
#################################################################
{%- set stig_id = 'RHEL-07-030000' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat1/files' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}
{%- set svcName = 'auditd.service' %}

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
start_{{ stig_id }}-{{ svcName }}:
  service.running:
    - name: '{{ svcName }}'
    - enable: True
{%- endif %}
