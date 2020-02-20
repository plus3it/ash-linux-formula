# Finding ID:	RHEL-07-030820
# Version:	RHEL-07-030820_rule
# SRG ID:	SRG-OS-000480-GPOS-00227
# Finding Level:	medium
# 
# Rule Summary:
#	The system must update the DoD-approved virus scan program
#	every seven days or more frequently.
#
# CCI-001668 
#    NIST SP 800-53 :: SI-3 a 
#    NIST SP 800-53A :: SI-3.1 (ii) 
#
#################################################################
{%- set stig_id = 'RHEL-07-030820' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat2/files' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}
{%- set selParm = 'antivirus_can_scan_system' %}
{%- set selValu = '1' %}
{%- if salt.pkg.version('MSFElinux') %}
  {%- set NAIdir = '/opt/NAI/LinuxShield/engine/dat' %}
{%- elif salt.pkg.version('clamav-scanner-systemd') and
         salt.pkg.version('clamav') %}
  {%- set svcName = 'clamd@scan' %}
  {%- set clamCfg = '/etc/clamd.d/scan.conf' %}
{%- else %}
  {%- set svcName = 'None' %}
{%- endif %}

script_{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stig_id }}.sh
    - cwd: /root

{%- if svcName == 'None' %}
service_{{ stig_id }}-{{ svcName }}:
  cmd.run:
    - name: 'printf "\nchanged=no comment=''No approved A/V service components found: This will be a finding.''\n"'
    - cwd: /root
    - stateful: True
{%- else %}

  # Configure SEL rule if SEL is enabled (alert if not)
  {% if salt.selinux.getenforce == 'Disabled' %}
sebool_{{ stig_id }}-{{ selParm }}:
  cmd.run:
    - name: 'printf "\nchanged=no comment=''SELinux disabled: this will be a finding.''\n"'
    - cwd: /root
    - stateful: True
  {%- else %}
sebool_{{ stig_id }}-{{ selParm }}:
  module.run:
    - name: 'selinux.setsebool'
    - boolean: '{{ selParm }}'
    - value: '{{ selValu }}'
    - persist: True
  {%- endif %}

  {%- if svcName == 'clamd@scan' %}
file_{{ stig_id }}-{{ clamCfg }}-example:
  file.comment:
    - name: '{{ clamCfg }}'
    - regex: '^Example$'
    - char: '#'
file_{{ stig_id }}-{{ clamCfg }}-socket:
  file.uncomment:
    - name: '{{ clamCfg }}'
    - regex: 'LocalSocket '
    - char: '#'
  {%- endif %}

service_{{ stig_id }}-{{ svcName }}:
  service.running:
    - name: '{{ svcName }}'
    - enable: True
{%- endif %}
