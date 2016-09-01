# Finding ID:	RHEL-07-040230
# Version:	RHEL-07-040230_rule
# SRG ID:	SRG-OS-000384-GPOS-00167
# Finding Level:	medium
# 
# Rule Summary:
#	The operating system, if using PKI-based authentication, must
#	implement a local cache of revocation data to certificate
#	validation in case of the inability to access revocation
#	information via the network.
#
# CCI-001991 
#    NIST SP 800-53 Revision 4 :: IA-5 (2) (d) 
#
#################################################################
{%- set stig_id = 'RHEL-07-040230' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat2/files' %}

script_{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stig_id }}.sh
    - cwd: /root

