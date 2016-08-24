# Finding ID:	RHEL-07-020150
# Version:	RHEL-07-020150_rule
# SRG ID:	SRG-OS-000366-GPOS-00153
# Finding Level:	high
#
# Rule Summary:
#	The operating system must prevent the installation of
#	software, patches, service packs, device drivers, or
#	operating system components from a repository without
#	verification they have been digitally signed using a
#	certificate that is issued by a Certificate Authority (CA)
#	that is recognized and approved by the organization.
#
# CCI-001749
#    NIST SP 800-53 Revision 4 :: CM-5 (3)
#
#################################################################
{%- stig_id = 'RHEL-07-020150' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat1/files' %}

script_{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stig_id }}.sh
    - cwd: /root
