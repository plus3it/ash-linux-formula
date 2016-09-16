# Finding ID:	RHEL-07-040040
# Version:	RHEL-07-040040_rule
# SRG ID:	SRG-OS-000067-GPOS-00035
# Finding Level:	medium
# 
# Rule Summary:
#	The operating system, for PKI-based authentication, must
#	enforce authorized access to all PKI private keys stored or
#	used by the operating system.
#
# CCI-000186 
#    NIST SP 800-53 :: IA-5 (2) 
#    NIST SP 800-53A :: IA-5 (2).1 
#    NIST SP 800-53 Revision 4 :: IA-5 (2) 
#
#################################################################
{%- set stig_id = 'RHEL-07-040040' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat2/files' %}

script_{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stig_id }}.sh
    - cwd: /root

