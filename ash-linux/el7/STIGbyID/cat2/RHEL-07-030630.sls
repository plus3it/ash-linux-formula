# Finding ID:	RHEL-07-030630
# Version:	RHEL-07-030630_rule
# SRG ID:	SRG-OS-000471-GPOS-00215
# Finding Level:	medium
# 
# Rule Summary:
#	All uses of the pam_timestamp_check command must be audited.
#
# CCI-000172 
#    NIST SP 800-53 :: AU-12 c 
#    NIST SP 800-53A :: AU-12.1 (iv) 
#    NIST SP 800-53 Revision 4 :: AU-12 c 
#
#################################################################
{%- set stig_id = 'RHEL-07-030630' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat2/files' %}

script_{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stig_id }}.sh
    - cwd: /root

