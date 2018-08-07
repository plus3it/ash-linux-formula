# Finding ID:	RHEL-07-020260
# Version:	SV-86623r3_rule
# SRG ID:	SRG-OS-000480-GPOS-00227
# Finding Level:	medium
# Finding ID RHEL-07-020260
# 
# Rule Summary:
#	System security patches and updates must be installed and up to date.
#
# CCI-000366 
#    NIST SP 800-53 :: CM-6 b 
#    NIST SP 800-53A :: CM-6.1 (iv) 
#    NIST SP 800-53 Revision 4 :: CM-6 b 
#
#################################################################
{%- set stig_id = 'RHEL-07-020260' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat2/files' %}

upgrade_{{ stig_id }}:
  pkg.uptodate
