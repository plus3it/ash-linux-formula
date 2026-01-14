# Ref Doc:
#   - STIG - RHEL 9 v2r6      (01 Oct 2025)
#   - STIG - OEL 9 v1r3       (01 Oct 2025)
#   - STIG - AlmaLinux 9 v1r4 (01 Oct 2025)
# Finding ID:
#   - RHEL: V-258146
#   - OEL:  V-271854
#   - Alma: V-269513
# Rule ID:
#   - RHEL: SV-258146r1045288_rule
#   - OEL:  SV-271854r1092274_rule
#   - Alma: SV-269513r1050396_rule
# STIG ID:
#   - RHEL-09-652040
#   - OL09-00-005015
#   - ALMA-09-052600
# SRG ID:     SRG-OS-NNNNNN-GPOS-NNNNN
#
# Finding Level: medium
#
# Rule Summary:
#       The OS must authenticate the remote logging server for offloading audit
#       logs via rsyslog
#
# References:
#   CCI:
#     - CCI-001851
#   NIST:
#     - SP 800-53 Revision 4 :: AU-4 (1)
#
###########################################################################
{%- set stigIdByVendor = {
    'AlmaLinux': 'ALMA-09-052600',
    'CentOS Stream': 'RHEL-09-652040',
    'OEL': 'OL09-00-005015',
    'RedHat': 'RHEL-09-652040',
    'Rocky': 'RHEL-09-652040',
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
    grep='\$ActionSendStreamDriverAuthMode'
  )
%}

{{ stig_id }}-description:
  test.show_notification:
    - text: |-
        ----------------------------------------
        STIG Finding ID: {{ stig_id }}
            The OS must authenticate the remote
            logging server for offloading audit
            logs via rsyslog
        ----------------------------------------

{%- if stig_id in skipIt %}
notify_{{ stig_id }}-skipSet:
  test.show_notification:
    - text: |
        Handler for {{ stig_id }} has been selected for skip.
{%- else %}
  {%- for rsyslogCfgFile in rsyslogCfgFiles %}
Fix $ActionSendStreamDriverAuthMode setting in {{ rsyslogCfgFile }} ({{ stig_id }}):
  file.replace:
    - name: '{{ rsyslogCfgFile }}'
    - backup: False
    - watch_in:
      - service: 'Re-read rsyslog configuration-options'
    - pattern: '^(\s*)(\$ActionSendStreamDriverAuthMode\s*).*'
    - repl: '\1\2x509/name'
  {%- else %}
Fix $ActionSendStreamDriverAuthMode setting in {{ rsyslogDefCfgfile }} ({{ stig_id }}):
  file.replace:
    - name: '{{ rsyslogDefCfgfile }}'
    - append_if_not_found: True
    - backup: False
    - not_found_content: |
        # Set per rule {{ stig_id }}
        $ActionSendStreamDriverAuthMode x509/name
    - watch_in:
      - service: 'Re-read rsyslog configuration-options'
    - pattern: '^(\s*)(\$ActionSendStreamDriverAuthMode\s*).*'
    - repl: '\1\2x509/name'
  {%- endfor %}
{%- endif %}

Re-read rsyslog configuration-options:
  service.running:
    - name: 'rsyslog.service'
    - enable: true
    - reload: false
    - onlyif:
      - '[[ $( systemctl is-active rsyslog.service ) == "active" ]]'

