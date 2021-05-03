# Finding ID:	RHEL-07-021910
# Version:	RHEL-07-021910_rule
# SRG ID:	SRG-OS-000095-GPOS-00049
# Finding Level:	high
#
# Rule Summary:
#	The telnet-server package must not be installed.
#
# CCI-000381
#    NIST SP 800-53 :: CM-7
#    NIST SP 800-53A :: CM-7.1 (ii)
#    NIST SP 800-53 Revision 4 :: CM-7 a
#
#################################################################
{%- set stig_id = 'RHEL-07-021910' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat1/files' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}

script_{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stig_id }}.sh
    - cwd: /root

{%- if stig_id in skipIt %}
notify_{{ stig_id }}-skipSet:
  cmd.run:
    - name: 'printf "\nchanged=no comment=''Handler for {{ stig_id }} has been selected for skip.''\n"'
    - stateful: True
    - cwd: /root
{%- else %}
package_{{ stig_id }}-nuke:
  pkg.removed:
    - name: 'telnet-server'
{%- endif %}
