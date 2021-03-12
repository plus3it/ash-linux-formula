# Finding ID:	RHEL-07-031010
# Version:	RHEL-07-031010_rule
# SRG ID:	SRG-OS-000480-GPOS-00227
# Finding Level:	medium
#
# Rule Summary:
#	The rsyslog daemon must not accept log messages from other
#	servers unless the server is being used for log aggregation.
#
# CCI-000368
# CCI-000318
# CCI-001812
# CCI-001813
# CCI-001814
#    NIST SP 800-53 :: CM-6 c
#    NIST SP 800-53A :: CM-6.1 (v)
#    NIST SP 800-53 Revision 4 :: CM-6 c
#    NIST SP 800-53 :: CM-3 e
#    NIST SP 800-53A :: CM-3.1 (v)
#    NIST SP 800-53 Revision 4 :: CM-3 f
#    NIST SP 800-53 Revision 4 :: CM-11 (2)
#    NIST SP 800-53 Revision 4 :: CM-5 (1)
#    NIST SP 800-53 Revision 4 :: CM-5 (1)
#
#################################################################
{%- set stig_id = 'RHEL-07-031010' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat2/files' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}

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
disable_{{ stig_id }}-imtcp:
  file.comment:
    - name: '/etc/rsyslog.conf'
    - regex: ^\$ModLoad imtcp
    - char: '#'
{%- endif %}
