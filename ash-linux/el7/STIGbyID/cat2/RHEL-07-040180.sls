# Finding ID:	RHEL-07-040180
# Version:	RHEL-07-040180_rule
# SRG ID:	SRG-OS-000250-GPOS-00093
# Finding Level:	medium
#
# Rule Summary:
#	The operating system must implement cryptography to protect the
#	integrity of Lightweight Directory Access Protocol (LDAP)
#	authentication communications.
#
# CCI-001453
#    NIST SP 800-53 :: AC-17 (2)
#    NIST SP 800-53A :: AC-17 (2).1
#    NIST SP 800-53 Revision 4 :: AC-17 (2)
#
#################################################################
{%- set stig_id = 'RHEL-07-040180' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat2/files' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}
{%- set authCfg = '/etc/sysconfig/authconfig' %}
{%- set ldapCfg = '/etc/pam_ldap.conf' %}

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
notice_{{ stig_id }}-BadSTIG:
  cmd.run:
    - name: 'printf "\nchanged=no comment=''Per https://access.redhat.com/solutions/1198543, {{ ldapCfg }} has been deprecated in favor of SSSD''\n"'
    - cwd: /root
    - stateful: True
{%- endif %}
