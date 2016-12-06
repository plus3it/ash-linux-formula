# Finding ID:	RHEL-07-040830
# Version:	RHEL-07-040830_rule
# SRG ID:	SRG-OS-000480-GPOS-00227
# Finding Level:	medium
# 
# Rule Summary:
#	The system must not have unauthorized IP tunnels configured.
#
# CCI-000366 
#    NIST SP 800-53 :: CM-6 b 
#    NIST SP 800-53A :: CM-6.1 (iv) 
#    NIST SP 800-53 Revision 4 :: CM-6 b 
#
#################################################################
{%- set stig_id = 'RHEL-07-040830' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat2/files' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}
{%- set chkPkg = 'libreswan' %}
{%- set svcName = 'ipsec' %}
{%- set cfgFile = '/etc/ipsec.conf' %}

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
  {%- if salt.pkg.version(chkPkg) %}
notice_{{ stig_id }}-{{ chkPkg }}:
  cmd.run:
    - name: 'printf "\nchanged=no comment=''Potential finding: {{ chkPkg }} is installed.''\n"'
    - stateful: True
    - cwd: /root
    {%- if salt.file.search(cfgFile, '^conn ') %}
notice_{{ stig_id }}-{{ cfgFile }}:
  cmd.run:
    - name: 'printf "\nchanged=no comment=''Potential finding: {{ cfgFile }} contains tunnel defenitions.''\n"'
    - stateful: True
    - cwd: /root
    {%- else %}
notice_{{ stig_id }}-{{ cfgFile }}:
  cmd.run:
    - name: 'printf "\nchanged=no comment=''IPSEC configuration file ({{ cfgFile }}) contains no tunnel defenitions.''\n"'
    - stateful: True
    - cwd: /root
    {%- endif %}
  {%- else %}
notice_{{ stig_id }}-{{ chkPkg }}:
  cmd.run:
    - name: 'printf "\nchanged=no comment=''Package {{ chkPkg }} is not installed.''\n"'
    - stateful: True
    - cwd: /root
  {%- endif %}
  {%- if salt.service.available(svcName) %}
notice_{{ stig_id }}-{{ svcName }}:
  cmd.run:
    - name: 'printf "\nchanged=no comment=''Potential finding: {{ svcName }} is running.''\n"'
    - stateful: True
    - cwd: /root
  {%- else %}
notice_{{ stig_id }}-{{ svcName }}:
  cmd.run:
    - name: 'printf "\nchanged=no comment=''Service {{ svcName }} is not running.''\n"'
    - stateful: True
    - cwd: /root
  {%- endif %}
{%- endif %}
