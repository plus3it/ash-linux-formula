# Ref Doc:
#   - STIG - RHEL 9 vXrY      (01 Oct 2025)
#   - STIG - OEL 9 vXrY       (01 Oct 2025)
#   - STIG - AlmaLinux 9 vXrY (01 Oct 2025)
# Finding ID:
#   - RHEL: V-258149
#   - OEL:  V-271852
#   - Alma: V-269517
# Rule ID:
#   - RHEL: SV-258149r1106462_rule
#   - OEL:  SV-271852r1092608_rule
#   - Alma: SV-269517r1050400_rule
# STIG ID:
#   - RHEL-09-652055
#   - OL09-00-005005
#   - ALMA-09-053040
# SRG ID:     SRG-OS-000479-GPOS-00224
#   - SRG-OS-000480-GPOS-00227
#   - SRG-OS-000342-GPOS-00133
#
# Finding Level: medium
#
# Rule Summary:
#       The OS must be configured to forward audit records via TCP to a
#       different system or media from the system being audited via rsyslog
#
# References:
#   CCI:
#     - CCI-001851
#   NIST:
#     - SP 800-53 Revision 4 :: AU-4 (1)
#
###########################################################################
{%- set stigIdByVendor = {
    'AlmaLinux': 'ALMA-09-053040',
    'CentOS Stream': 'RHEL-09-652055',
    'OEL': 'OL09-00-005005',
    'RedHat': 'RHEL-09-652055',
    'Rocky': 'RHEL-09-652055',
} %}
{%- set osName = salt.grains.get('os') %}
{%- set stig_id = stigIdByVendor[osName] %}
{%- set helperLoc = tpldir ~ '/files' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}
{%- set log_collector = salt.pillar.get('ash-linux:lookup:rsyslog:collector_host', []) %}
{%- set rsyslogDefCfgfile = '/etc/rsyslog.conf' %}
{%- set rsyslogCfgFiles = [] %}
{%- set searchDir = '/etc/rsyslog.d' %}
{%- set rsyslogCfgFiles = rsyslogCfgFiles + salt.file.find(
    searchDir,
    type='f',
    name='*.conf',
    grep='\*\.\*'
  )
%}

{{ stig_id }}-description:
  test.show_notification:
    - text: |-
        ----------------------------------------
        STIG Finding ID: {{ stig_id }}
            The OS must be configured to forward
            audit records via TCP to a different
            system or media from the system
            being audited via rsyslog
        ----------------------------------------

{%- if stig_id in skipIt %}
notify_{{ stig_id }}-skipSet:
  test.show_notification:
    - text: |
        Handler for {{ stig_id }} has been selected for skip.
{%- elif log_collector %}
  {%- for rsyslogCfgFile in rsyslogCfgFiles %}
Set log-destination in {{ rsyslogCfgFile }} to {{ log_collector }} via TCP ({{ stig_id }}):
  file.replace:
    - name: '{{ rsyslogCfgFile }}'
    - append_if_not_found: True
    - backup: False
    - not_found_content: |
        # Set per rule {{ stig_id }}
        *.* @@{{ log_collector }}
    - pattern: '(^\*\.\*\s*)(:omrelp:|@*)(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|[a-z]*\.[a-z.]*)(:\d*|)'
    - repl: '\g<1>@@{{ log_collector }}'
    - watch_in:
      - service: 'Re-read rsyslog configuration-options ({{ stig_id }})'
  {%- else %}
Set log-destination in {{ rsyslogDefCfgfile }} to {{ log_collector }} via TCP ({{ stig_id }}):
  file.replace:
    - name: '{{ rsyslogDefCfgfile }}'
    - append_if_not_found: True
    - backup: False
    - not_found_content: |
        # Set per rule {{ stig_id }}
        *.* @@{{ log_collector }}
    - pattern: '(^\*\.\*\s*)(:omrelp:|@*)(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|[a-z]*\.[a-z.]*)(:\d*|)'
    - repl: '\g<1>@@{{ log_collector }}'
    - watch_in:
      - service: 'Re-read rsyslog configuration-options ({{ stig_id }})'
  {%- endfor %}
{%- else %}
No Collector Specified ({{ stig_id }}):
  test.show_notification:
    - text: |
        No syslog collector hostname/IP found in Pillar-data
{%- endif %}


Re-read rsyslog configuration-options ({{ stig_id }}):
  service.running:
    - name: 'rsyslog.service'
    - enable: true
    - reload: false
    - onlyif:
      - '[[ $( systemctl is-active rsyslog.service ) == "active" ]]'
