# Finding ID:	RHEL-07-010072
# Version:	RHEL-07-010072_rule
# SRG ID:	SRG-OS-000029-GPOS-00010
# Finding Level:	medium
# 
# Rule Summary:
#	The operating system must have the screen package installed.
#
# CCI-000057 
#    NIST SP 800-53 :: AC-11 a 
#    NIST SP 800-53A :: AC-11.1 (ii) 
#    NIST SP 800-53 Revision 4 :: AC-11 a 
#
#################################################################
{%- set stig_id = 'RHEL-07-010072' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat2/files' %}
{%- set pkgName = 'screen' %}

script_{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stig_id }}.sh
    - cwd: /root

package_{{ pkgName }}:
  pkg.installed:
    - name: '{{ pkgName }}'
