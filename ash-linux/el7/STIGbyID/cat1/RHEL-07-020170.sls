# Finding ID:	RHEL-07-020170
# Version:	RHEL-07-020170_rule
# SRG ID:	SRG-OS-000405-GPOS-00184
# Finding Level:	high
#
# Rule Summary:
#	Operating systems handling data requiring data-at-rest
#	protections must employ cryptographic mechanisms to prevent
#	unauthorized disclosure and modification of the information
#	at rest.
#
# CCI-002476
# CCI-001199
#    NIST SP 800-53 Revision 4 :: SC-28 (1)
#    NIST SP 800-53 :: SC-28
#    NIST SP 800-53A :: SC-28.1
#    NIST SP 800-53 Revision 4 :: SC-28
#
#################################################################
{%- stig_id = 'RHEL-07-020170' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat1/files' %}

script_{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stig_id }}.sh
    - cwd: /root
