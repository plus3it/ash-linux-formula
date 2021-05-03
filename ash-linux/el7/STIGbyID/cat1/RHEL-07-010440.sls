# STIG ID:	RHEL-07-010440
# Rule ID:	SV-86577r2_rule
# Vuln ID:	V-71953
# SRG ID:	SRG-OS-000480-GPOS-00229
# Finding Level:	high
#
# Rule Summary:
#	The operating system must not allow an unattended or
#	automatic logon to the system via a graphical user interface.
#
# CCI-000366
#    NIST SP 800-53 :: CM-6 b
#    NIST SP 800-53A :: CM-6.1 (iv)
#    NIST SP 800-53 Revision 4 :: CM-6 b
#
#################################################################
{%- set stig_id = 'RHEL-07-010440' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat1/files' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}
{%- set checkFile = '/etc/gdm/custom.conf'%}
{%- set checkParm = 'AutomaticLoginEnable'%}

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
  {%- if not salt.pkg.version('gdm') %}
eval_{{ stig_id }}:
  cmd.run:
    - name: 'printf "\nchanged=no comment=''GDM susbsystem is not installed.''\n"'
    - cwd: /root
    - stateful: True
  {%- elif salt.file.search(checkFile, '^' + checkParm) %}
file_{{ stig_id }}:
  file.replace:
    - name: {{ checkFile }}
    - pattern: '^{{ checkParm }}.*$'
    - repl: '{{ checkParm }}=false'
  {%- else %}
file_{{ stig_id }}:
  file.replace:
    - name: {{ checkFile }}
    - pattern: '^\[daemon]'
    - repl: '[daemon]\n{{ checkParm }}=false'
  {%- endif %}
{%- endif %}
