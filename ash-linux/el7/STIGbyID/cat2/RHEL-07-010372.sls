# Finding ID:	RHEL-07-010372
# Version:	RHEL-07-010372_rule
# SRG ID:	SRG-OS-000329-GPOS-00128
# Finding Level:	medium
# 
# Rule Summary:
#	Accounts subject to three unsuccessful login attempts within
#	15 minutes must be locked for the maximum configurable period.
#
# CCI-002238 
#    NIST SP 800-53 Revision 4 :: AC-7 b 
#
#################################################################
{%- set stig_id = 'RHEL-07-010372' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat2/files' %}

script_{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stig_id }}.sh
    - cwd: /root

