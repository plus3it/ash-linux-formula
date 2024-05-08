# Ref Doc:    STIG - RHEL 9 v1r3 (24 Apr 2024)
# Finding ID: V-257989
# Rule ID:    SV-257989r943014_rule
# STIG ID:    RHEL-09-255065
# SRG ID:     SRG-OS-000250-GPOS-00093
#
# Finding Level: medium
#
# Rule Summary:
#       RHEL 9 must implement DOD-approved encryption ciphers to protect the
#       confidentiality of SSH client connections.
#
# References:
# CCI:
#   - CCI-001453
# NIST SP 800-53 :: AC-17 (2)
# NIST SP 800-53A :: AC-17 (2).1
# NIST SP 800-53 Revision 4 :: AC-17 (2)
#
###########################################################################
{%- set stig_id = 'RHEL-09-255065' %}
{%- set helperLoc = tpldir ~ '/files' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}
{%- set cfgFile = '/etc/crypto-policies/back-ends/opensshserver.config' %}
{%- set fixOpts = [
        'aes256-gcm@openssh.com',
        'chacha20-poly1305@openssh.com',
        'aes256-ctr',
        'aes128-gcm@openssh.com',
        'aes128-ctr'
] %}

{{ stig_id }}-description:
  test.show_notification:
    - text: |
        --------------------------------------
        STIG Finding ID: V-257989
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
    - pattern: '(^Ciphers\s\s*)(.*$)'
    - repl: '\g<1>{{ fixOpts|join(',') }}'
{%- endif %}
