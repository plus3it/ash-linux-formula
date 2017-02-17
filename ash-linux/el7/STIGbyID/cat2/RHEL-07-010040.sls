# Finding ID:	RHEL-07-010040
# Version:	RHEL-07-010040_rule
# SRG ID:	SRG-OS-000023-GPOS-00006
# Finding Level:	medium
# 
# Rule Summary:
#	The operating system must display the Standard Mandatory DoD
#	Notice and Consent Banner before granting local or remote
#	access to the system via a command line user logon.
#
# CCI-000048 
#    NIST SP 800-53 :: AC-8 a 
#    NIST SP 800-53A :: AC-8.1 (ii) 
#    NIST SP 800-53 Revision 4 :: AC-8 a 
#
#################################################################
{%- set stig_id = 'RHEL-07-010040' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat2/files' %}
{%- set bannerText = 'ash-linux/el7/banner-consent_full.txt' %}

script_{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stig_id }}.sh
    - cwd: /root

file_{{ stig_id }}:
  file.managed:
    - name: '/etc/issue'
    - source: salt://{{ bannerText }}
    - user: root
    - group: root
    - mode: 0644

