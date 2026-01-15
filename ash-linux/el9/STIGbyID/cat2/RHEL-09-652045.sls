# Ref Doc:
#   - STIG - RHEL 9 v2r6      (01 Oct 2025)
#   - STIG - OEL 9 v1r3       (01 Oct 2025)
#   - STIG - AlmaLinux 9 v1r4 (01 Oct 2025)
#   - STIG - AL2023 v1r1      (14 Jul 2025)
# Finding ID:
#   - RHEL:   V-258147
#   - OEL:    V-271855
#   - Alma:   V-269514
#   - AL2023: V-274153
# Rule ID:
#   - RHEL:   SV-258147r1045290_rule
#   - OEL:    SV-271855r1092277_rule
#   - Alma:   SV-269514r1050397_rule
#   - AL2023: SV-274078r1120222_rule
# STIG ID:
#   - RHEL-09-652045
#   - OL09-00-005020
#   - ALMA-09-052710
#   - AZLX-23-002070
# SRG ID:
#   - SRG-OS-000342-GPOS-00133
#   - SRG-OS-000479-GPOS-00224
#
# Finding Level: medium
#
# Rule Summary:
#       The OS must encrypt the transfer of audit records offloaded onto a
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
    'AlmaLinux': 'ALMA-09-052710',
    'Amazon': 'AZLX-23-002070',
    'CentOS Stream': 'RHEL-09-652045',
    'OEL': 'OL09-00-005020',
    'RedHat': 'RHEL-09-652045',
    'Rocky': 'RHEL-09-652045',
} %}
{%- set osName = salt.grains.get('os') %}
{%- set stig_id = stigIdByVendor[osName] %}
{%- set helperLoc = tpldir ~ '/files' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}
{%- set rsyslogCfgFiles = [] %}
{%- set rsyslogDefCfgfile = '/etc/rsyslog.conf' %}
{%- set searchDir = '/etc/rsyslog.d' %}
{%- set rsyslogCfgFiles = rsyslogCfgFiles + salt.file.find(
    searchDir,
    type='f',
    name='*.conf',
    grep='\$ActionSendStreamDriverMode'
  )
%}

{{ stig_id }}-description:
  test.show_notification:
    - text: |-
        ----------------------------------------
        STIG Finding ID: {{ stig_id }}
            The OS must encrypt the transfer of
            audit records offloaded onto a
            different system or media from the
            system being audited via rsyslog
            logs via rsyslog
        ----------------------------------------

{%- if stig_id in skipIt %}
notify_{{ stig_id }}-skipSet:
  test.show_notification:
    - text: |
        Handler for {{ stig_id }} has been selected for skip.
{%- else %}
  {%- for rsyslogCfgFile in rsyslogCfgFiles %}
Fix $ActionSendStreamDriverMode setting in {{ rsyslogCfgFile }} ({{ stig_id }}):
  file.replace:
    - name: '{{ rsyslogCfgFile }}'
    - backup: False
    - watch_in:
      - service: 'Re-read rsyslog configuration-options ({{ stig_id }})'
    - pattern: '^(\s*)(\$ActionSendStreamDriverMode\s*).*'
    - repl: '\1\21'
  {%- else %}
Fix $ActionSendStreamDriverMode setting in {{ rsyslogDefCfgfile }} ({{ stig_id }}):
  file.replace:
    - name: '{{ rsyslogDefCfgfile }}'
    - append_if_not_found: True
    - backup: False
    - not_found_content: |
        # Set per rule {{ stig_id }}
        $ActionSendStreamDriverMode 1
    - watch_in:
      - service: 'Re-read rsyslog configuration-options ({{ stig_id }})'
    - pattern: '^(\s*)(\$ActionSendStreamDriverMode\s*).*'
    - repl: '\1\21'
  {%- endfor %}
{%- endif %}

Re-read rsyslog configuration-options ({{ stig_id }}):
  service.running:
    - name: 'rsyslog.service'
    - enable: true
    - reload: false
    - onlyif:
      - '[[ $( systemctl is-active rsyslog.service ) == "active" ]]'

