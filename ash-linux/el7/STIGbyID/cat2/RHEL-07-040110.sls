# Finding ID:	RHEL-07-040110
# Version:	RHEL-07-040110_rule
# SRG ID:	SRG-OS-000033-GPOS-00014
# Finding Level:	medium
# 
# Rule Summary:
#	A FIPS 140-2 approved cryptographic algorithm must be used for
#	SSH communications.
#
# CCI-000068 
# CCI-000366 
# CCI-000803 
#    NIST SP 800-53 :: AC-17 (2) 
#    NIST SP 800-53A :: AC-17 (2).1 
#    NIST SP 800-53 Revision 4 :: AC-17 (2) 
#    NIST SP 800-53 :: CM-6 b 
#    NIST SP 800-53A :: CM-6.1 (iv) 
#    NIST SP 800-53 Revision 4 :: CM-6 b 
#    NIST SP 800-53 :: IA-7 
#    NIST SP 800-53A :: IA-7.1 
#    NIST SP 800-53 Revision 4 :: IA-7 
#
#################################################################
{%- set stig_id = 'RHEL-07-040110' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat2/files' %}

script_{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stig_id }}.sh
    - cwd: /root

