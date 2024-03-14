# Ref Doc:    STIG - RHEL 8 v1r11
# Finding ID: V-230252
# Rule ID:    SV-230252r917873_rule
# STIG ID:    RHEL-08-010291
# SRG ID:     SRG-OS-000250-GPOS-00093
#
# Finding Level: medium
#
# Rule Summary:
#       The operating system must implement DoD-approved encryption to protect
#       the confidentiality of SSH server connections
#
# References:
#   CCI:
#     - CCI-001453
#         NIST SP 800-53 :: AC-17 (2)
#         NIST SP 800-53A :: AC-17.1 (2).1
#         NIST SP 800-53 Revision 4 :: AC-17 (2)
#
###########################################################################
{%- set stig_id = 'RHEL-08-010291' %}
{%- set helperLoc = tpldir ~ '/files' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}
{%- set cfgFile = '/etc/crypto-policies/back-ends/opensshserver.config' %}
{%- set fixOpts = [
  'aes256-ctr',
  'aes192-ctr',
  'aes128-ctr',
  'aes256-gcm@openssh.com',
  'aes128-gcm@openssh.com'
] %}

{{ stig_id }}-description:
  test.show_notification:
    - text: |
        --------------------------------------
        STIG Finding ID: V-230252
             The OS must allow only DoD-
             approved SSH encryption-ciphers
        --------------------------------------

{%- if stig_id in skipIt %}
notify_{{ stig_id }}-skipSet:
  test.show_notification:
    - text: |
        Handler for {{ stig_id }} has been selected for skip.
{%- else %}
Set SSHD Ciphers:
  file.replace:
    - name:  '{{ cfgFile }}'
    - pattern: "(^CRYPTO_POLICY='.*)(-oCiphers=[a-z0-9,@.-]*)(.*'$)"
    - repl: '\g<1>-oCiphers={{ fixOpts|join(',') }}\g<3>'
{%- endif %}
