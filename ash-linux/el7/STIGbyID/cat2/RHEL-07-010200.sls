# Finding ID:	RHEL-07-010200
# Version:	RHEL-07-010200_rule
# SRG ID:	SRG-OS-000075-GPOS-00043
# Finding Level:	medium
# 
# Rule Summary:
#	Passwords for new users must be restricted to a 24 hours/1 day
#	minimum lifetime.
#
# CCI-000198 
#    NIST SP 800-53 :: IA-5 (1) (d) 
#    NIST SP 800-53A :: IA-5 (1).1 (v) 
#    NIST SP 800-53 Revision 4 :: IA-5 (1) (d) 
#
#################################################################
{%- set stig_id = 'RHEL-07-010200' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat2/files' %}

script_{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stig_id }}.sh
    - cwd: /root

