# Finding ID:	RHEL-07-020140
# Version:	RHEL-07-020140_rule
# SRG ID:	SRG-OS-000363-GPOS-00150
# Finding Level:	medium
# 
# Rule Summary:
#	Designated personnel must be notified if baseline configurations
#	are changed in an unauthorized manner.
#
# CCI-001744 
#    NIST SP 800-53 Revision 4 :: CM-3 (5) 
#
#################################################################
{%- set stig_id = 'RHEL-07-020140' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat2/files' %}

script_{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stig_id }}.sh
    - cwd: /root

