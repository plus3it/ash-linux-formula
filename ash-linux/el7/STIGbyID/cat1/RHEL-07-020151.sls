# Finding ID:	RHEL-07-020151
# Version:	RHEL-07-020151_rule
# SRG ID:	SRG-OS-000366-GPOS-00153
# Finding Level:	high
#
# Rule Summary:
#	The operating system must prevent the installation of
#	software, patches, service packs, device drivers, or
#	operating system components of local packages without
#	verification they have been digitally signed using a
#	certificate that is issued by a Certificate Authority (CA)
#	that is recognized and approved by the organization.
#
# CCI-001749
#    NIST SP 800-53 Revision 4 :: CM-5 (3)
#
#################################################################
{%- set stig_id = 'RHEL-07-020151' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat1/files' %}
{%- set checkFile = '/etc/yum.conf'%}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}

script_{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stig_id }}.sh
    - cwd: /root

{%- if stig_id in skipIt %}
notify_{{ stig_id }}-skipSet:
  cmd.run:
    - name: 'printf "\nchanged=no comment=''Handler for {{ stig_id }} has been selected for skip.''\n"'
    - cwd: /root
{%- else %}
  {%- if salt.file.search(checkFile, '^localpkg_gpgcheck') %}
file_{{ stig_id }}-{{ checkFile }}:
  file.replace:
    - name: '{{ checkFile }}'
    - pattern: '^localpkg_gpgcheck.*$'
    - repl: 'localpkg_gpgcheck=1'
  {%- else %}
file_{{ stig_id }}-{{ checkFile }}:
  file.replace:
    - name: '{{ checkFile }}'
    - pattern: '^\[main]'
    - repl: '[main]\nlocalpkg_gpgcheck=1'
  {%- endif %}
{%- endif %}
