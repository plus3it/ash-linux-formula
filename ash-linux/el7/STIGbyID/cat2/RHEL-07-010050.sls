# STIG ID:	RHEL-07-010050
# Rule ID:	SV-86487r3_rule
# Vuln ID:	V-71863
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
{%- set stig_id = 'RHEL-07-010050' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat2/files' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}
{%- import_text "ash-linux/el7/banner-consent_full.txt" as default_banner %}
{%- set bannerText = salt.pillar.get('ash-linux:lookup:login-banners:/etc/issue', default_banner) %}


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
file_{{ stig_id }}:
  file.managed:
    - name: '/etc/issue'
    - user: root
    - group: root
    - mode: 0644
    - contents: {{ bannerText|yaml(False)|indent(8) }}
{%- endif %}
