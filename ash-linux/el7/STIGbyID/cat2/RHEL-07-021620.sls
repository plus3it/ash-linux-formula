# Finding ID:	RHEL-07-021620
# Version:	RHEL-07-021620_rule
# SRG ID:	SRG-OS-000480-GPOS-00227
# Finding Level:	medium
#
# Rule Summary:
#	The file integrity tool must use FIPS 140-2 approved
#	cryptographic hashes for validating file contents and
#	directories.
#
# CCI-000366
#    NIST SP 800-53 :: CM-6 b
#    NIST SP 800-53A :: CM-6.1 (iv)
#    NIST SP 800-53 Revision 4 :: CM-6 b
#
#################################################################
{%- set stig_id = 'RHEL-07-021620' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat2/files' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}
{%- set cfgFile = '/etc/aide.conf' %}

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
pkg_{{ stig_id }}-aide:
  pkg.installed:
    - name: 'aide'

fixcfg_{{ stig_id }}-{{ cfgFile }}:
  cmd.run:
    - name: 'awk ''{ if (/^\// && !/sha512/) printf("%s+sha512\n",$0);
             else print $0}'' {{ cfgFile }} > /tmp/{{ stig_id }} && mv
             /tmp/{{ stig_id }} {{ cfgFile }}'
    - cwd: /root
    - require:
      - pkg: 'pkg_{{ stig_id }}-aide'

setDefault_{{ stig_id }}-{{ cfgFile }}:
  file.replace:
    - name: {{ cfgFile }}
    - pattern: '^\s*NORMAL\s*=\s*.*$'
    - repl: 'NORMAL = FIPSR+sha512'
    - require:
      - cmd: 'fixcfg_{{ stig_id }}-{{ cfgFile }}'
{%- endif %}
