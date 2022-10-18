# Ref Doc:    STIG - RHEL 9 v1r7
# Finding ID: V-230484
# Rule ID:    SV-230484r627750_rule
# STIG ID:    RHEL-08-030740
# SRG ID:     SRG-OS-000355-GPOS-00143
#
# Finding Level: medium
#
# Rule Summary:
#       If using NTP, the operating system must be configured to use
#       `server` directives instead of `pool` directives
#
# References:
#   CCI:
#     - CCI-001891
#   NIST SP 800-53 Revision 4 :: AU-8 (1) (a)
#
###########################################################################
{%- set stig_id = 'RHEL-08-030740' %}
{%- set helperLoc = 'ash-linux/el8/STIGbyID/cat2/files' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}
{%- set targFile = '/etc/chrony.conf' %}
{%- if salt.grains.get('os')|lower == 'redhat' %}
  {%- set ntpVendor = 'rhel' %}
{%- endif %}
{%- set ntpServerList = salt.pillar.get('ash-linux:lookup:ntp-servers', [
    "0.{{ ntpVendor }}.pool.ntp.org",
    "1.{{ ntpVendor }}.pool.ntp.org",
    "2.{{ ntpVendor }}.pool.ntp.org"
]) %}

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
file_{{ stig_id }}-{{ targFile }}:
  file.replace:
    - name: {{ targFile }}
    - pattern: '^(?P<srctok>^(|\s*)pool\s* .*$)'
    - repl: '# Set per STIG-ID {{ stig_id }}\n# \g<srctok>\n'
  {%- endif %}
  {%- for ntpServer in ntpServerList.items() %}
file_{{ stig_id }}-{{ targFile }}-{{ ntpServer }}:
  file.append:
    - name: {{ targFile }}
    - text:
      - server {{ ntpServer }} iburst maxpoll 16
{%- endif %}

