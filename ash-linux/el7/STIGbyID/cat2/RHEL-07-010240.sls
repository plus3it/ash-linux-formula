# Finding ID:	RHEL-07-010240
# Version:	RHEL-07-010240_rule
# SRG ID:	SRG-OS-000077-GPOS-00045
# Finding Level:	medium
# 
# Rule Summary:
#	Passwords must be prohibited from reuse for a minimum of five generations.
#
# CCI-000200 
#    NIST SP 800-53 :: IA-5 (1) (e) 
#    NIST SP 800-53A :: IA-5 (1).1 (v) 
#    NIST SP 800-53 Revision 4 :: IA-5 (1) (e) 
#
#################################################################
{%- set stig_id = 'RHEL-07-010240' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat2/files' %}

script_{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stig_id }}.sh
    - cwd: /root

