# Ref Doc:
#   - STIG - RHEL 9 v2r6      (01 Oct 2025)
#   - STIG - OEL 9 v1r3       (01 Oct 2025)
#   - STIG - AlmaLinux 9 v1r4 (01 Oct 2025)
#   - STIG - AL2023 v1r1      (14 Jul 2025)

# Finding ID:
#   - RHEL:   V-257945
#   - OEL:    V-271699
#   - Alma:   V-269535
#   - AL2023: V-274175
# Rule ID:
#   - RHEL:   SV-257945r1038944_rule
#   - OEL:    SV-271699r1091809_rule
#   - Alma:   SV-269535r1050418_rule
#   - AL2023: SV-274175r1120659_rule
# STIG ID:
#   - RHEL-09-252020
#   - OL09-00-002323
#   - ALMA-09-055350
#   - AZLX-23-002565
# SRG ID:     SRG-OS-000356-GPOS-00144
#   - SRG-OS-000355-GPOS-00143
#   - SRG-OS-000359-GPOS-00146
#   - SRG-OS-000785-GPOS-00250
#
# Finding Level: medium
#
# Rule Summary:
#       The OS must must securely compare internal information system clocks at
#       least every 24 hours
#
# References:
#   CCI:
#     - CCI-001890
#       NIST:
#         - SP 800-53 Revision 4 :: AU-8 b
#     - CCI-001891
#       NIST:
#         - SP 800-53 Revision 4 :: AU-8 (1) (a)
#     - CCI-002046
#       NIST:
#         - SP 800-53 Revision 4 :: AU-8 (1) (b)
#
###########################################################################
{%- set stigIdByVendor = {
    'AlmaLinux': 'ALMA-09-055350',
    'Amazon': 'AZLX-23-002565',
    'CentOS Stream': 'RHEL-09-252020',
    'OEL': 'OL09-00-002323',
    'RedHat': 'RHEL-09-252020',
    'Rocky': 'RHEL-09-252020',
} %}
{%- set osName = salt.grains.get('os') %}
{%- set stig_id = stigIdByVendor[osName] %}
{%- set helperLoc = tpldir ~ '/files' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}
{%- set targFile = '/etc/chrony.conf' %}
{%- set serverFile = '/etc/chrony.d/servers.conf' %}
{%- set ntpByVendor = {
    'AlmaLinux': [
        "0.almalinux.pool.ntp.org",
        "1.almalinux.pool.ntp.org",
        "2.almalinux.pool.ntp.org",
    ],
    'Amazon': [
        "169.254.169.123",
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
{%- set maxpollPower = salt.pillar.get('ash-linux:lookup:chrony:maxpoll', '16') %}

{{ stig_id }}-description:
  test.show_notification:
    - text: |-
        ----------------------------------------
        STIG Finding ID: {{ stig_id }}
            The OS must must securely compare
            internal information system clocks
            at least every 24 hours
        ----------------------------------------

{%- if stig_id in skipIt %}
notify_{{ stig_id }}-skipSet:
  test.show_notification:
    - text: |
        Handler for {{ stig_id }} has been selected for skip.
{%- else %}
  {%- for ntpServer in ntpServerList %}
Ensure {{ ntpServer }} in {{ targFile }} ({{ stig_id }}):
  file.replace:
    - name: '{{ targFile }}'
    - append_if_not_found: True
    - backup: False
    - not_found_content: |
        # Set per rule {{ stig_id }}
        server {{ ntpServer }} iburst maxpoll {{ maxpollPower }}
    - pattern: '^(\s\s*|)server.*{{ ntpServer }}.*'
    - repl: 'server {{ ntpServer }} iburst maxpoll {{ maxpollPower }}'
    - watch_in:
      - service: 'Re-read chronyd configuration-options ({{ stig_id }})'
  {%- endfor %}
{%- endif %}

Re-read chronyd configuration-options ({{ stig_id }}):
  service.running:
    - name: 'chronyd.service'
    - enable: true
    - reload: false
    - onlyif:
      - '[[ $( systemctl is-active chronyd.service ) == "active" ]]'
