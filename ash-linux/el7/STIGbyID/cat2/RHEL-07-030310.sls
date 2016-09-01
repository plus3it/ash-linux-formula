# Finding ID:	RHEL-07-030310
# Version:	RHEL-07-030310_rule
# SRG ID:	SRG-OS-000327-GPOS-00127
# Finding Level:	medium
# 
# Rule Summary:
#	All privileged function executions must be audited.
#
# CCI-002234 
#    NIST SP 800-53 Revision 4 :: AC-6 (9) 
#
#################################################################
{%- set stig_id = 'RHEL-07-030310' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat2/files' %}

script_{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stig_id }}.sh
    - cwd: /root

