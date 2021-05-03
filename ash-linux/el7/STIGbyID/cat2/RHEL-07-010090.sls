# STIG ID:	RHEL-07-010090
# Rule ID:	SV-86521r3_rule
# Vuln ID:	V-71897
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
{%- set stig_id = 'RHEL-07-010090' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat2/files' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}
{%- set pkgName = 'screen' %}

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
package_{{ pkgName }}:
  pkg.installed:
    - name: '{{ pkgName }}'
{%- endif %}
