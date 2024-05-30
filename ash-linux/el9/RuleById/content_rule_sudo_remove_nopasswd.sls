# Rule ID:              content_rule_sudo_remove_nopasswd
# Finding Level:        medium
#
# Rule Summary:
#       All sudoers must be configured to authenticate with a password:
#       * Without re-authentication, users may access resources or perform tasks
#         for which they do not have authorization.
#       * When operating systems provide the capability to escalate a functional
#         capability, it is critical that the user re-authenticate.
#
# References:
#   - ANSSI
#     - BP28(R5)
#     - BP28(R59)
#   - CIS-CSC
#     - 1
#     - 12
#     - 15
#     - 16
#     - 5
#   - COBIT5
#     - DSS05.04
#     - DSS05.10
#     - DSS06.03
#     - DSS06.10
#   - DISA
#     - CCI-002038
#   - ISA-62443-2009
#     - 4.3.3.5.1
#     - 4.3.3.6.1
#     - 4.3.3.6.2
#     - 4.3.3.6.3
#     - 4.3.3.6.4
#     - 4.3.3.6.5
#     - 4.3.3.6.6
#     - 4.3.3.6.7
#     - 4.3.3.6.8
#     - 4.3.3.6.9
#   - ISA-62443-2013
#     - SR 1.1
#     - SR 1.10
#     - SR 1.2
#     - SR 1.3
#     - SR 1.4
#     - SR 1.5
#     - SR 1.7
#     - SR 1.8
#     - SR 1.9
#   - ISO27001-2013
#     - A.18.1.4
#     - A.9.2.1
#     - A.9.2.2
#     - A.9.2.3
#     - A.9.2.4
#     - A.9.2.6
#     - A.9.3.1
#     - A.9.4.2
#     - A.9.4.3
#   - NIST
#     - IA-11
#     - CM-6(a)
#   - NIST-CSF
#     - PR.AC-1
#     - PR.AC-7
#   - OS-SRG
#     - SRG-OS-000373-GPOS-00156
#     - SRG-OS-000373-GPOS-00157
#     - SRG-OS-000373-GPOS-00158
#
#################################################################
{%- set stig_id = 'sudo_remove_nopasswd' %}
{%- set helperLoc = tpldir ~ '/files' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}
{%- set biosVendor = salt.grains.get('biosvendor', []) %}
{%- set sudoerFiles = [ '/etc/sudoers' ] %}
{%- set sudoerFiles = sudoerFiles + salt.file.find('/etc/sudoers.d', maxdepth=1, type='f') %}

{{ stig_id }}-description:
  test.show_notification:
    - text: |
        --------------------------------------
        STIG Finding ID: {{ stig_id }}
             All sudoers must authenticate for
             each requested command
        --------------------------------------

{%- if stig_id in skipIt %}
notify_{{ stig_id }}-skipSet:
  test.show_notification:
    - text: |
        Handler for {{ stig_id }} has been selected for skip.
{%- else %}
  {%- for sudoer in sudoerFiles %}
    {%- if sudoer != "/etc/sudoers.d/90-cloud-init-users" and salt.file.search(sudoer, '^[a-zA-Z%@].*NOPASSWD') %}
Nuke NOPASSWD from sudoers ({{ stig_id }}) - {{ sudoer }}:
  file.replace:
    - name: '{{ sudoer }}'
    - pattern: '^([a-zA-Z0-9_-][a-zA-Z0-9._-]*)(\s\s*.*)(NOPASSWD:[A-Za-z/_-]*)'
    - repl: '# Set per STIG-ID {{ stig_id }}\n\1\2'
    {%- elif sudoer == "/etc/sudoers.d/90-cloud-init-users" and salt.file.search(sudoer, '^[a-zA-Z%@].*NOPASSWD') %}
Why Skip ({{ stig_id }}) - is {{ biosVendor }}:
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
