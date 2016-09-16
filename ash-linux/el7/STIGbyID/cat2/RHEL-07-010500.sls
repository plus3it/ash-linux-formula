# Finding ID:	RHEL-07-010500
# Version:	RHEL-07-010500_rule
# SRG ID:	SRG-OS-000104-GPOS-00051
# Finding Level:	medium
# 
# Rule Summary:
#	The operating system must uniquely identify and must
#	authenticate organizational users (or processes acting on
#	behalf of organizational users) using multi-factor
#	authentication.
#
# CCI-000766 
#    NIST SP 800-53 :: IA-2 (2) 
#    NIST SP 800-53A :: IA-2 (2).1 
#    NIST SP 800-53 Revision 4 :: IA-2 (2) 
#
#################################################################
{%- set stig_id = 'RHEL-07-010500' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat2/files' %}

script_{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stig_id }}.sh
    - cwd: /root

