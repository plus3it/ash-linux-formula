# Finding ID:	RHEL-07-030010
# Version:	RHEL-07-030010_rule
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
{%- set stig_id = 'RHEL-07-030010' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat1/files' %}
{%- set svcName = 'auditd.service' %}

script_{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stig_id }}.sh
    - cwd: /root

start_{{ stig_id }}-{{ svcName }}:
  service.running:
    - name: '{{ svcName }}'

enable_{{ stig_id }}-{{ svcName }}:
  service.enabled:
    - name: '{{ svcName }}'

