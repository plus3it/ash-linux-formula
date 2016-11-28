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
{%- set kernType = 'dracut-fips' %}
{%- set grub2cfg = '/boot/grub2/grub.cfg' %}
{%- set fipsChk = '/proc/sys/crypto/fips_enabled' %}

script_{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stig_id }}.sh
    - cwd: /root

{%- if salt.pkg.version(kernType) %}
notify_{{ stig_id }}-kernWarn:
  cmd.run:
    - name: 'echo "STIG-compatible kernel-extensions available."'
    - cwd: /root
  {%- if salt.file.search(grub2cfg, 'fips=1') %}
notify_{{ stig_id }}-{{ grub2cfg }}:
  cmd.run:
    - name: 'echo "At least one boot-menu entry has FIPS-mode enabled."'
    - cwd: /root
  {%- else %}
notify_{{ stig_id }}-{{ grub2cfg }}:
  cmd.run:
    - name: 'echo "No boot-menu entries have FIPS-mode enabled." > /dev/stderr && exit 1'
    - cwd: /root
  {%- endif %}
  {%- if salt.file.search(fipsChk, '^1') %}
notify_{{ stig_id }}-{{ fipsChk }}:
  cmd.run:
    - name: 'echo "FIPS-mode active in {{ fipsChk }}."'
    - cwd: /root
  {%- else %}
notify_{{ stig_id }}-{{ fipsChk }}:
  cmd.run:
    - name: 'echo "FIPS-mode not active in {{ fipsChk }}." > /dev/stderr && exit 1'
    - cwd: /root
  {%- endif %}
{%- else %}
notify_{{ stig_id }}-kernWarn:
  cmd.run:
    - name: 'printf "STIG-compatible kernel-extensions not available.\n" > /dev/stderr && exit 1'
    - cwd: /root
{%- endif %}
