# Ref Doc:    STIG - RHEL 9 v2r5
# Finding ID: V-272496
# Rule ID:    content_rule_selinux_context_elevation_for_sudo
# STIG ID:    RHEL-09-431016
# SRG ID:     SRG-OS-000445-GPOS-00199
#
# Finding Level: medium
#
# Rule Summary:
#       The OS must elevate the SELinux context when an administrator calls the
#       sudo command
#
# References:
#   - CCI:
#     - CCI-002235
#   - NIST:
#     -  SP 800-53 Revision 4 :: AC-6 (10)
#
###########################################################################
{%- set stig_id = 'RHEL-09-431016' %}
{%- set helperLoc = tpldir ~ '/files' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}
{%- set biosVendor = salt.grains.get('biosvendor', []) %}
{%- set sudoerFiles = [ '/etc/sudoers' ] %}
{%- set sudoerFiles = sudoerFiles + salt.file.find('/etc/sudoers.d', maxdepth=1, type='f') %}

{{ stig_id }}-description:
  test.show_notification:
    - text: |
        --------------------------------------
        STIG Finding ID: V-272496
             The OS must elevate the SELinux
             context when an administrator
             calls the sudo command
        --------------------------------------

{%- if stig_id in skipIt %}
notify_{{ stig_id }}-skipSet:
  test.show_notification:
    - text: |
        Handler for {{ stig_id }} has been selected for skip.
{%- else %}
  {%- for sudoerFile in sudoerFiles %}
    {%- if (
             sudoerFile != "/etc/sudoers.d/90-cloud-init-users" and
             sudoerFile != "/etc/sudoers.d/ssm-agent-users"
           )  %}
Ensure users and groups have SEL ROLE and TYPE transition-mappings ({{ stig_id }}) - {{ sudoerFile }}:
  file.replace:
    - name: '{{ sudoerFile }}'
    - append_if_not_found: False
    - backup: False
    - pattern: '^(|%)([a-z0-9_^-]*\s\s*)([A-Z]*=\([A-Za-z]*\)\s\s*)(?!(TYPE|ROLE)=[a-z_]*)([A-Za-z:]*)$'
    - repl: '\1\2\3 TYPE=sysadm_t ROLE=sysadm_r \5'

Ensure users and groups have consistent SEL ROLE and TYPE transition-mappings ({{ stig_id }}) - {{ sudoerFile }}:
  file.replace:
    - name: '{{ sudoerFile }}'
    - append_if_not_found: False
    - backup: False
    - pattern: '^(|%)([a-z0-9_^-]*\s\s*)([A-Z]*=\([a-zA-Z]*\)\s\s*)(TYPE=[a-z]*_t\s\s*)(ROLE=[a-z]*_r\s\s*)([A-Z]*$)'
    - repl: '\1\2\3\tTYPE=sysadm_t\tROLE=sysadm_r\t\6'

    {%- elif (
               sudoerFile == "/etc/sudoers.d/90-cloud-init-users" or
               sudoerFile == "/etc/sudoers.d/ssm-agent-users"
             ) %}
Why Skip ({{ stig_id }}) - {{ sudoerFile }}:
  test.show_notification:
    - text: |
        --------------------------------------------------
        SKIPPING: Enabling this control on {{ biosVendor }}
        could break the ability of the provisioning-user
        and/or "special" accounts (e.g., the "SSM-user"
        account) from being able to function as designed
        --------------------------------------------------
    {%- endif %}
  {%- endfor %}
{%- endif %}
