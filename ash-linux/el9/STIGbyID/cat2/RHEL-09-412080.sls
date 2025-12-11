# Ref Doc:
#   - STIG - RHEL 9 v2r6      (01 Oct 2025)
#   - STIG - AlmaLinux 9 v1r4 (01 Oct 2025)
#   - STIG - AL2023 v1r1      (14 Jul 2025)
# Finding ID:
#   - RHEL:   V-258077
#   - Alma:   V-269421
#   - AL2023: V-274166
# Rule ID:
#   - RHEL:   SV-258077r1014874_rule
#   - Alma:   SV-269421r1050304_rule
#   - AL2023: SV-274166r1120486_rule
# STIG ID:
#   - RHEL-09-412080
#   - ALMA-09-040500
#   - AZLX-23-002510
# SRG ID:     SRG-OS-000163-GPOS-00072
#
# Finding Level: medium
#
# Rule Summary:
#       The OS must ...
#
# References:
#   CCI:
#     - CCI-001133
#   NIST:
#     - SP 800-53 :: SC-10
#     - SP 800-53A :: SC-10.1 (ii)
#     - SP 800-53 Revision 4 :: SC-10
#
###########################################################################
{%- set helperLoc = tpldir ~ '/files' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}
{%- set stigIdByVendor = {
    'AlmaLinux': 'ALMA-09-040500',
    'Amazon': 'AZLX-23-002510',
    'CentOS Stream': 'RHEL-09-412080',
    'OEL': 'OL09-00-UNDEF',
    'RedHat': 'RHEL-09-412080',
    'Rocky': 'RHEL-09-412080',
} %}
{%- set stig_id = stigIdByVendor[salt.grains.get('os')] %}
{%- set osName = salt.grains.get('os') %}
{%- set chkFile = '/etc/systemd/logind.conf' %}
{%- set chkParm = 'StopIdleSessionSec' %}
{%- set parmVal = salt.pillar.get('ash-linux:lookup:logind_conf:idle_max', '900') %}

{{ stig_id }}-description:
  test.show_notification:
    - text: |-
        ----------------------------------------
        STIG Finding ID: {{ stig_id }}
             The OS must ...
        ----------------------------------------

{%- if stig_id in skipIt %}
notify_{{ stig_id }}-skipSet:
  test.show_notification:
    - text: |
        Handler for {{ stig_id }} has been selected for skip.
{%- elif osName != 'OEL' %}
Set {{ chkParm }} to {{ parmVal }}:
  file.replace:
    - name: '{{ chkFile }}'
    - append_if_not_found: True
    - not_found_content: |
        # Set per rule {{ stig_id }}
        {{ chkParm }}={{ parmVal }}
    - watch_in:
      - service: 'Re-read {{ chkFile }}'
    - pattern: '^(|\s\s*)StopIdleSessionSec=\d\d*'
    - repl: '{{ chkParm }}={{ parmVal }}'
{%- else %}
Skip Reason ({{ stig_id }}):
  test.show_notification:
    - text: |-
        ----------------------------------------
        STIG Finding ID: {{ stig_id }}
             Not valid for distro '{{ osName }}'
        ----------------------------------------
    - onchanges_in:
      - service: 'Re-read {{ chkFile }}'
{%- endif %}

Re-read {{ chkFile }}:
  service.running:
    - name: 'systemd-logind'
    - enable: true
    - reload: false
