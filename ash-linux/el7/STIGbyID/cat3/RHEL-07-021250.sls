# Finding ID:	RHEL-07-021250
# Version:	RHEL-07-021250_rule
# SRG ID:	SRG-OS-000480-GPOS-00227
# Finding Level:	low
# 
# Rule Summary:
#	The system must use a separate file system for /var.
#
# CCI-000366 
#    NIST SP 800-53 :: CM-6 b 
#    NIST SP 800-53A :: CM-6.1 (iv) 
#    NIST SP 800-53 Revision 4 :: CM-6 b 
#
#################################################################
{%- set stig_id = 'RHEL-07-021250' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat3/files' %}
{%- set chkPtn = '/var' %}
{%- set fstab = salt.mount.fstab().keys() %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}

script_{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stig_id }}.sh
    - cwd: /root

{%- if stig_id in skipIt %}
{%- else %}
  {%- if chkPtn in fstab %}
status_{{ stig_id }}-fstab:
  cmd.run:
    - name: 'printf "\nchanged=no comment=''Found {{ chkPtn }} in /etc/fstab file: config ok.''\n"'
    - cwd: /root
    - stateful: True
  {%- else %}
status_{{ stig_id }}-fstab:
  cmd.run:
    - name: 'printf "\nchanged=no comment=''Did not find {{ chkPtn }} in /etc/fstab file: this will be a finding.''\n"'
    - cwd: /root
    - stateful: True
  {%- endif %}
{%- endif %}
