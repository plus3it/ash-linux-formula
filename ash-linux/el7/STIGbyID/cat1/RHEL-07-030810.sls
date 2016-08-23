# Finding ID:	RHEL-07-030810
# Version:	RHEL-07-030810_rule
# SRG ID:	SRG-OS-000480-GPOS-00227
# Finding Level:	high
# 
# Rule Summary:
#	The system must use a DoD-approved virus scan program.
#
# CCI-001668 
#    NIST SP 800-53 :: SI-3 a 
#    NIST SP 800-53A :: SI-3.1 (ii) 
#
#################################################################
{%- stig_id = 'RHEL-07-030810' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat1/files' %}

script_{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stig_id }}.sh
    - cwd: /root
