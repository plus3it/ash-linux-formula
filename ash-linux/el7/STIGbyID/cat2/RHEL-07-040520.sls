# Finding ID:	RHEL-07-040520
# Version:	RHEL-07-040520_rule
# SRG ID:	SRG-OS-000480-GPOS-00227
# Finding Level:	medium
#
# Rule Summary:
#	If the Trivial File Transfer Protocol (TFTP) server is required,
#	the TFTP daemon must be configured to operate in secure mode.
#
# CCI-000366
#    NIST SP 800-53 :: CM-6 b
#    NIST SP 800-53A :: CM-6.1 (iv)
#    NIST SP 800-53 Revision 4 :: CM-6 b
#
#################################################################
{%- set stig_id = 'RHEL-07-040520' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat2/files' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}
{%- set pkgChk = 'tftp-server' %}
{%- set cfgFile = '/etc/xinetd.d/tftp' %}

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
  {%- if salt.pkg.version(pkgChk) %}
file_{{ stig_id }}-{{ cfgFile }}:
  file.replace:
    - name: '{{ cfgFile }}'
    - pattern: 'server_args\s=\s.*$'
    - repl: 'server_args\t= -s /var/lib/tftpboot'
  {%- else %}
file_{{ stig_id }}-{{ cfgFile }}:
  cmd.run:
    - name: 'printf "\nchanged=no comment=''{{ pkgChk }} package not installed. Skipping.''\n"'
    - cwd: /root
    - stateful: True
  {%- endif %}
{%- endif %}
