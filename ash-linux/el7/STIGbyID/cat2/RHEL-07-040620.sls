# Finding ID:	RHEL-07-040620
# Version:	RHEL-07-040620_rule
# SRG ID:	SRG-OS-000250-GPOS-00093
# Finding Level:	medium
# 
# Rule Summary:
#	The SSH daemon must be configured to only use Message
#	Authentication Codes (MACs) employing FIPS 140-2 approved
#	cryptographic hash algorithms.
#
# CCI-001453 
#    NIST SP 800-53 :: AC-17 (2) 
#    NIST SP 800-53A :: AC-17 (2).1 
#    NIST SP 800-53 Revision 4 :: AC-17 (2) 
#
#################################################################
{%- set stig_id = 'RHEL-07-040620' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat2/files' %}

script_{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stig_id }}.sh
    - cwd: /root

