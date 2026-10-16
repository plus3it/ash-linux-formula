# Ref Doc:
#   - STIG - RHEL 9 v2r6      (01 Oct 2025)
#   - STIG - OEL 9 vXrY       (01 Oct 2025)
#   - STIG - AlmaLinux 9 v1r4 (01 Oct 2025)
# Finding ID:
#   - RHEL: V-258037
#   - OEL:  V-271700
#   - Alma: V-269465
# Rule ID:
#   - RHEL: SV-258037r1014863_rule
#   - OEL:  SV-271700r1091812_rule
#   - Alma: SV-269465r1050348_rule
# STIG ID:
#   - RHEL-09-291025
#   - OL09-00-002330
#   - ALMA-09-046550
# SRG ID:
#   - SRG-OS-000062-GPOS-00031
#   - SRG-OS-000477-GPOS-00222
#
# Finding Level: medium
#
# Rule Summary:
#       The OS must must enable Linux audit logging for the USBGuard daemon
#
# References:
#   CCI:
#     - CCI-000169
#     - CCI-000172
#   NIST:
#     - SP 800-53 :: AU-12 a, AU-12 c
#     - SP 800-53A :: AU-12.1 (ii), AU-12.1 (iv)
#     - SP 800-53 Revision 4 :: AU-12 a, AU-12 c
#
###########################################################################
{%- set stigIdByVendor = {
    'AlmaLinux': 'ALMA-09-046550',
    'Amazon': 'RHEL-09-291025',
    'CentOS Stream': 'RHEL-09-291025',
    'OEL': 'OL09-00-002330',
    'RedHat': 'RHEL-09-291025',
    'Rocky': 'RHEL-09-291025',
} %}
{%- set stig_id = stigIdByVendor[salt.grains.get('os')] %}
{%- set helperLoc = tpldir ~ '/files' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}
{%- set cfgFile = '/etc/usbguard/usbguard-daemon.conf' %}
{%- set cfgParm = 'AuditBackend' %}
{%- set cfgValu = salt.pillar.get('ash-linux:lookup:usb_guard:audit_backend', 'LinuxAudit') %}

{{ stig_id }}-description:
  test.show_notification:
    - text: |-
        ----------------------------------------
        STIG Finding ID: {{ stig_id }}
            The OS must must enable Linux audit
            logging for the USBGuard daemon
        ----------------------------------------

{%- if stig_id in skipIt %}
notify_{{ stig_id }}-skipSet:
  test.show_notification:
    - text: |
        Handler for {{ stig_id }} has been selected for skip.
{%- else %}
# Establish correct mode and user/group ownership
# -   Create a null-file if no file already exists
# -   Ensures correct mode & user/group ownership on file (irrespective of
#     file's previous existence)
Ensure {{ cfgFile }} exists with strict permissions ({{ stig_id }}):
  file.managed:
    - group: 'root'
    - makedirs: True
    - mode: '0600'
    - name: '{{ cfgFile }}'
    - replace: False
    - user: 'root'

# Ensurse STIG-prescribed config-directive exists in file
Enable USBguard audit-logging ({{ stig_id }}):
  file.replace:
    - append_if_not_found: True
    - name: '{{ cfgFile }}'
    - not_found_content: |
        # Set per rule {{ stig_id }}
        {{ cfgParm }}={{ cfgValu }}
    - pattern: '(^(|\s\s*)){{ cfgParm }}.*$'
    - repl: '{{ cfgParm }}={{ cfgValu }}'
    - require:
      - file: 'Ensure {{ cfgFile }} exists with strict permissions ({{ stig_id }})'

# Bypasses the broken file.managed SELinux parameter on RHEL 9/10 and ensures
# that label matches the rule from `matchpathcon`
Apply SELinux context to {{ cfgFile }} ({{ stig_id }}):
  selinux.fcontext_policy_applied:
    - name: '{{ cfgFile }}'
    - require:
      - file: 'Enable USBguard audit-logging ({{ stig_id }})'
{%- endif %}
