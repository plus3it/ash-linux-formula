# Rule ID:              content_rule_chronyd_server_directive
# Finding Level:        medium
#
# Rule Summary:
#       Make sure that Chrony only has time sources configured
#       with the `server` directive
#
# Identifiers:
#   - content_rule_chronyd_server_directive
#
# References:
#   - DISA
#     - CCI-001891
#   - OS-SRG
#     - SRG-OS-000355-GPOS-00143
#     - SRG-OS-000356-GPOS-00144
#     - SRG-OS-000359-GPOS-00146
##################################################################
{%- set stig_id = 'chronyd_server_directive' %}
{%- set helperLoc = tpldir ~ '/files' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}
{%- set useNtp = salt.pillar.get('ash-linux:lookup:use-ntp', 'False') %}
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

{{ stig_id }}-description:
  test.show_notification:
    - text: |
        --------------------------------------
        STIG Finding ID: {{ stig_id }}
             Use server directives when using
             chronyd for time-synchronization
        --------------------------------------

{%- if stig_id in skipIt %}
notify_{{ stig_id }}-skipSet:
  test.show_notification:
    - text: |
        Handler for {{ stig_id }} has been selected for skip.
{%- elif useNtp == 'True' %}
# Get rid of `pool` directives
file_{{ stig_id }}-{{ targFile }}_poolDirectives:
  file.replace:
    - name: '{{ targFile }}'
    - pattern: '^(?P<srctok>^(|\s*)pool\s* .*$)'
    - repl: '# \g<srctok>\t# ''pool'' directives disabled per STIG\n'

# Remove "stock" `server` references from main config-file
file_{{ stig_id }}-{{ targFile }}_serverDirectives:
  file.replace:
    - name: '{{ targFile }}'
    - pattern: '^(?P<srctok>^(|\s*)server\s* .*$)'
    - repl: '# \g<srctok>\t# ''server'' entries managed in {{ serverFile }}\n'

# Set `server` references to an included file
file_{{ stig_id }}-{{ targFile }}-addInclude:
  file.append:
    - name: {{ targFile }}
    - text: |

        # All server configuration directives managed in this file
        include {{ serverFile }}

# Populate included-file
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
    - selinux:
        serange: 's0'
        serole: 'object_r'
        setype: 'etc_t'
        seuser: 'system_u'
    - user: 'root'
{%- else %}
Why Skip ({{ stig_id }}) - NTP Servers:
  test.show_notification:
    - text: |
        --------------------------------------
        STIG Finding ID: {{ stig_id }}
          No valid values for Chrony `server`
          directives found for configuring
          service for externally-sourced
          time-synchronization information.
        --------------------------------------
{%- endif %}
