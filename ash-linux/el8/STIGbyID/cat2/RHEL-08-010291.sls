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
{%- set helperLoc = 'ash-linux/el8/STIGbyID/cat2/files' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}
{%- set cfgFile = '/etc/crypto-policies/back-ends/opensshserver.config' %}
{%- set fixOpts = [
  'aes256-ctr',
  'aes192-ctr',
  'aes128-ctr',
  'aes256-gcm@openssh.com',
  'aes128-gcm@openssh.com'
] %}

script_{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stig_id }}.sh
    - cwd: /root

{%- if stig_id in skipIt %}
notify_{{ stig_id }}-skipSet:
  cmd.run:
    - name: 'printf "\nchanged=no comment=''Handler for {{ stig_id }} has been selected for skip.''\n"'
    - stateful: True
    - cwd: /root
{%- else %}
Set SSHD Ciphers:
  file.replace:
    - name:  '{{ cfgFile }}'
    - pattern: "(^CRYPTO_POLICY='.*)(-oCiphers=[a-z0-9,@.-]*)(.*'$)"
    - repl: '\g<1>-oCiphers={{ fixOpts|join(',') }}\g<3>'
{%- endif %}
