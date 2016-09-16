# Finding ID:	RHEL-07-030340
# Version:	RHEL-07-030340_rule
# SRG ID:	SRG-OS-000342-GPOS-00133
# Finding Level:	medium
# 
# Rule Summary:
#	The audit system must take appropriate action when the audit
#	storage volume is full.
#
# CCI-001851 
#    NIST SP 800-53 Revision 4 :: AU-4 (1) 
#
#################################################################
{%- set stig_id = 'RHEL-07-030340' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat2/files' %}

script_{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stig_id }}.sh
    - cwd: /root

