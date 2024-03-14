# Ref Doc:    STIG - RHEL 8 v1r12
# Finding ID: V-257258
# Rule ID:    SV-257258r917891_rule
# STIG ID:    RHEL-08-020035
# SRG ID:     SRG-OS-000163-GPOS-00072
#
# Finding Level: medium
#
# Rule Summary:
#       The Operating System must terminate idle user sessions
#
# References:
#   CCI:
#     - CCI-001133
#   NIST SP 800-53 :: SC-10
#   NIST SP 800-53A :: SC-10.1 (ii)
#   NIST SP 800-53 Revision 4 :: SC-10
#
###########################################################################
{%- set stig_id = 'RHEL-08-020035' %}
{%- set helperLoc = tpldir ~ '/files' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}
{%- set cfgFile = '/etc/systemd/logind.conf' %}
{%- set cfgParm = 'StopIdleSessionSec' %}
{%- set cfgValu = '900' %}
{%- set svcName = 'systemd-logind' %}

{{ stig_id }}-description:
  test.show_notification:
    - text: |
        --------------------------------------
        STIG Finding ID: V-257258
             The OS must terminate idle user
             sessions
        --------------------------------------

{%- if stig_id in skipIt %}
notify_{{ stig_id }}-skipSet:
  test.show_notification:
    - text: |
        Handler for {{ stig_id }} has been selected for skip.
{%- else %}
Set logind idle-session termination timeout:
  file.replace:
    - name: '{{ cfgFile }}'
    - append_if_not_found: True
    - not_found_content: |-

        # Inserted per {{ stig_id }}
        {{ cfgParm }}={{ cfgValu }}
    - pattern: '^(|#)\s*({{ cfgParm }}).*'
    - repl: '\g<2>={{ cfgValu }}'

service_{{ stig_id }}-{{ cfgFile }}:
  service.running:
    - name: '{{ svcName }}'
    - enable: True
    - watch:
      - file: 'Set logind idle-session termination timeout'
{%- endif %}
