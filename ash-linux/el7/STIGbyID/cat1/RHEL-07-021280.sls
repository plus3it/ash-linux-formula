# Finding ID:	RHEL-07-021280
# Version:	RHEL-07-021280_rule
# SRG ID:	SRG-OS-000033-GPOS-00014
# Finding Level:	high
#
# Rule Summary:
#	The operating system must implement NIST FIPS-validated
#	cryptography for the following: to provision digital
#	signatures, to generate cryptographic hashes, and to
#	protect unclassified information requiring confidentiality
#	and cryptographic protection in accordance with applicable
#	federal laws, Executive Orders, directives, policies,
#	regulations, and standards.
#
# CCI-000068
# CCI-002450
#    NIST SP 800-53 :: AC-17 (2)
#    NIST SP 800-53A :: AC-17 (2).1
#    NIST SP 800-53 Revision 4 :: AC-17 (2)
#    NIST SP 800-53 Revision 4 :: SC-13
#
#################################################################
{%- set stig_id = 'RHEL-07-021280' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat1/files' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}
{%- set kernType = 'dracut-fips' %}
{%- set grub2cfg = '/boot/grub2/grub.cfg' %}
{%- set fipsChk = 'crypto.fips_enabled' %}

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
  {%- if salt.pkg.version(kernType) %}
notify_{{ stig_id }}-kernWarn:
  cmd.run:
    - name: 'printf "\nchanged=no comment=''STIG-compatible kernel-extensions available.''\n"'
    - cwd: /root
    - stateful: True
    {%- if salt.file.search(grub2cfg, 'fips=1') %}
notify_{{ stig_id }}-{{ grub2cfg }}:
  cmd.run:
    - name: 'printf "\nchanged=no comment=''At least one boot-menu entry has FIPS-mode enabled.''\n"'
    - cwd: /root
    - stateful: True
    {%- else %}
notify_{{ stig_id }}-{{ grub2cfg }}:
  cmd.run:
    - name: 'printf "\nchanged=no comment=''WARNING: No boot-menu entries have FIPS-mode enabled.''\n"'
    - cwd: /root
    - stateful: True
    {%- endif %}
    {%- if salt.sysctl.get(fipsChk) %}
notify_{{ stig_id }}-{{ fipsChk }}:
  cmd.run:
    - name: 'printf "\nchanged=no comment=''FIPS-mode active in {{ fipsChk }}.''\n"'
    - cwd: /root
    - stateful: True
    {%- else %}
notify_{{ stig_id }}-{{ fipsChk }}:
  cmd.run:
    - name: 'printf "\nchanged=no comment=''WARNING: FIPS-mode not active in {{ fipsChk }}.''\n"'
    - cwd: /root
    - stateful: True
    {%- endif %}
  {%- else %}
notify_{{ stig_id }}-kernWarn:
  cmd.run:
    - name: 'printf "\nchanged=no comment=''WARNING: STIG-compatible kernel-extensions not available.''\n"'
    - cwd: /root
    - stateful: True
  {%- endif %}
{%- endif %}
