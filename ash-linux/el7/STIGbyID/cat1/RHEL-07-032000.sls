# Finding ID:	RHEL-07-032000
# Version:	RHEL-07-032000_rule
# SRG ID:	SRG-OS-000480-GPOS-00227
# Finding Level:	high
#
# Rule Summary:
#	The system must use a DoD-approved virus scan program.
#
# CCI-001668
#    NIST SP 800-53 :: SI-3 a
#    NIST SP 800-53A :: SI-3.1 (ii)
#
#################################################################
{%- set stig_id = 'RHEL-07-032000' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat1/files' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}
{%- set primeAV = 'MFEcma' %}
{%- set primeSvc = 'mcafee.ma' %}
{%- set secondAV = 'clamav' %}
{%- set secondSvc = 'clamd' %}

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
  {%- if salt.pkg.version(primeAV) %}
start_{{ stig_id }}-{{ primeSvc }}:
  service.running:
    - name: '{{ primeSvc }}'
    - enable: True

## STIG v0r2 content not accurate for Clam A/V
##   {%- elif salt.pkg.version(secondAV) %}
## start_{{ stig_id }}-{{ secondSvc }}:
##   service.running:
##     - name: '{{ secondSvc }}'
##
## enable_{{ stig_id }}-{{ secondSvc }}:
##   service.enabled:
##     - name: '{{ secondSvc }}'

  {%- else %}
missing_{{ stig_id }}-describe:
  cmd.run:
    - name: 'printf "\nchanged=no comment=''Was not able to find either McAfee or Clam A/V services installed. This will be a finding.''\n"'
    - cwd: /root
    - stateful: True
  {%- endif %}
{%- endif %}
