# Finding ID:	RHEL-07-040210
# Version:	RHEL-07-040210_rule
# SRG ID:	SRG-OS-000355-GPOS-00143
# Finding Level:	medium
#
# Rule Summary:
#	The operating system must, for networked systems, synchronize
#	clocks with a server that is synchronized to one of the
#	redundant United States Naval Observatory (USNO) time servers,
#	a time server designated for the appropriate DoD network
#	(NIPRNet/SIPRNet), and/or the Global Positioning System (GPS).
#
# CCI-001891
# CCI-002046
#    NIST SP 800-53 Revision 4 :: AU-8 (1) (a)
#    NIST SP 800-53 Revision 4 :: AU-8 (1) (b)
#
#################################################################
{%- set stig_id = 'RHEL-07-040210' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat2/files' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}
{%- set cfgFile = '/etc/ntp.conf' %}
{%- set parmName = 'maxpoll' %}
{%- set parmValu = '10' %}

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
file_{{ stig_id }}-{{ cfgFile }}:
  file.replace:
    - name: '{{ cfgFile }}'
    - pattern: '^\s{{ parmName }} .*$'
    - repl: '{{ parmName }} {{ parmValu }}'
    - append_if_not_found: True
    - not_found_content: |-
        # Inserted per STIG {{ stig_id }}
        {{ parmName }} {{ parmValu }}

service_{{ stig_id }}-{{ cfgFile }}:
  service.running:
    - name: ntpd
    - watch:
      - file: file_{{ stig_id }}-{{ cfgFile }}
{%- endif %}
