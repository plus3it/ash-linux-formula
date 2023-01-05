# Ref Doc:    STIG - RHEL 8 v1r7
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
{%- set serverFile = '/etc/chrony.d/servers.conf' %}
{%- set ntpByVendor = {
    'AlmaLinux': [
        "0.almalinux.pool.ntp.org",
        "1.almalinux.pool.ntp.org",
        "2.almalinux.pool.ntp.org",
    ],
    'CentOS Stream': [
        "0.centos.pool.ntp.org",
        "1.centos.pool.ntp.org",
        "2.centos.pool.ntp.org",
    ],
    'OEL': [
        "0.pool.ntp.org",
        "1.pool.ntp.org",
        "2.pool.ntp.org",
    ],
    'RedHat': [
        "0.rhel.pool.ntp.org",
        "1.rhel.pool.ntp.org",
        "2.rhel.pool.ntp.org",
    ],
    'Rocky': [
        "0.rocky.pool.ntp.org",
        "1.rocky.pool.ntp.org",
        "2.rocky.pool.ntp.org",
    ],
} %}
{%- set defNtpServers = ntpByVendor[salt.grains.get('os')] %}
{%- set ntpServerList = salt.pillar.get('ash-linux:lookup:ntp-servers', defNtpServers) %}

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
file_{{ stig_id }}-{{ targFile }}_poolDirectives:
  file.replace:
    - name: '{{ targFile }}'
    - pattern: '^(?P<srctok>^(|\s*)pool\s* .*$)'
    - repl: '# \g<srctok>\t# ''pool'' directives disabled per STIG\n'

file_{{ stig_id }}-{{ targFile }}_serverDirectives:
  file.replace:
    - name: '{{ targFile }}'
    - pattern: '^(?P<srctok>^(|\s*)server\s* .*$)'
    - repl: '# \g<srctok>\t# ''server'' entries managed in {{ serverFile }}\n'

file_{{ stig_id }}-{{ targFile }}-addInclude:
  file.append:
    - name: {{ targFile }}
    - text: |

        # All server configuration directives managed in this file
        include {{ serverFile }}

file_{{ stig_id }}-{{ targFile }}-includeFile:
  file.managed:
    - name: {{ serverFile }}
    - contents: |
        # NTP server-list
  {%- for ntpServer in ntpServerList %}
        server {{ ntpServer }} iburst maxpoll 16
  {%- endfor %}
    - create: True
    - group: 'root'
    - makedirs: True
    - mode: '0600'
    - replace: True
    - user: 'root'
{%- endif %}

