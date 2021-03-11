# Finding ID:	RHEL-07-040060
# Version:	RHEL-07-040060_rule
# SRG ID:	SRG-OS-000068-GPOS-00036
# Finding Level:	medium
#
# Rule Summary:
#	The cn_map file must have mode 0644 or less permissive.
#
# CCI-000187
#    NIST SP 800-53 :: IA-5 (2)
#    NIST SP 800-53A :: IA-5 (2).1
#    NIST SP 800-53 Revision 4 :: IA-5 (2) (c)
#
#################################################################
{%- set stig_id = 'RHEL-07-040060' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat2/files' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}
{%- set pkgChk = 'pam_pkcs11' %}
{%- set cfgFile = '/etc/pam_pkcs11/cn_map' %}

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
touch_{{ stig_id }}-{{ cfgFile }}:
  file.touch:
    - name: '{{ cfgFile }}'
    - makedirs: True
    - unless: ' test -e {{ cfgFile }}'

mode_{{ stig_id }}-{{ cfgFile }}:
  file.managed:
    - name: '{{ cfgFile }}'
    - mode: 0644
    - replace: False
    - require:
      - file: 'touch_{{ stig_id }}-{{ cfgFile }}'
{%- endif %}
