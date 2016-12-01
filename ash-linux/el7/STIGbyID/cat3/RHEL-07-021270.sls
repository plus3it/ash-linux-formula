# Finding ID:	RHEL-07-021270
# Version:	RHEL-07-021270_rule
# SRG ID:	SRG-OS-000480-GPOS-00227
# Finding Level:	low
# 
# Rule Summary:
#	The system must use a separate file system for /tmp (or equivalent).
#
# CCI-000366 
#    NIST SP 800-53 :: CM-6 b 
#    NIST SP 800-53A :: CM-6.1 (iv) 
#    NIST SP 800-53 Revision 4 :: CM-6 b 
#
#################################################################
{%- set stig_id = 'RHEL-07-021270' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat3/files' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}
{%- set chkPtn = '/tmp' %}
  #########################################################
  ## This kludge necessary to account for /tmp as either ##
  ## standard filesystem or tmpfs pseudo-filesystem.     ##
  #########################################################
{%- if salt.service.available('tmp.mount') %}
  {%- set fstab = [ '/tmp' ] %}
  {%- set mntMessage = chkPtn + ' managed by systemd' %}
{%- else %}
  {%- set fstab = salt.mount.fstab().keys() %}
  {%- set mntMessage = chkPtn + ' in /etc/fstab file' %}
{%- endif %}

script_{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stig_id }}.sh
    - cwd: /root

{%- if stig_id in skipIt %}
{%- else %}
  {%- if chkPtn in fstab %}
status_{{ stig_id }}-fstab:
  cmd.run:
    - name: 'printf "\nchanged=no comment=''Found {{ mntMessage }}: config ok.''\n"'
    - cwd: /root
    - stateful: True
  {%- else %}
status_{{ stig_id }}-fstab:
  cmd.run:
    - name: 'printf "\nchanged=no comment=''Did not find separate filesystem for {{ chkPtn }}: this will be a finding.''\n"'
    - cwd: /root
    - stateful: True
  {%- endif %}
{%- endif %}
