# Finding ID:	RHEL-07-010220
# Version:	RHEL-07-010220_rule
# SRG ID:	SRG-OS-000076-GPOS-00044
# Finding Level:	medium
# 
# Rule Summary:
#	Passwords for new users must be restricted to a 60-day maximum lifetime.
#
# CCI-000199 
#    NIST SP 800-53 :: IA-5 (1) (d) 
#    NIST SP 800-53A :: IA-5 (1).1 (v) 
#    NIST SP 800-53 Revision 4 :: IA-5 (1) (d) 
#
#################################################################
{%- set stig_id = 'RHEL-07-010220' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat2/files' %}

script_{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stig_id }}.sh
    - cwd: /root

