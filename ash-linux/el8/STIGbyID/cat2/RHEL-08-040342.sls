# Ref Doc:    STIG - RHEL 8 v1r12
# Finding ID: V-255924
# Rule ID:    SV-255924r917888_rule
# STIG ID:    RHEL-08-040342
# SRG ID:     SRG-OS-000250-GPOS-00093
#
# Finding Level: medium
#
# Rule Summary:
#       The SSH server must be configured to use only FIPS-validated key
#       exchange algorithms.
#
# References:
#   CCI:
#     - CCI-001453
#         NIST SP 800-53 :: AC-17 (2)
#         NIST SP 800-53A :: AC-17.1 (2).1
#         NIST SP 800-53 Revision 4 :: AC-17 (2)
#
###########################################################################
{%- set stig_id = 'RHEL-08-040342' %}
{%- set helperLoc = tpldir ~ '/files' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}
{%- set cfgFile = '/etc/crypto-policies/back-ends/opensshserver.config' %}
{%- set fixOpts = [
  'ecdh-sha2-nistp256',
  'ecdh-sha2-nistp384',
  'ecdh-sha2-nistp521',
  'diffie-hellman-group-exchange-sha256',
  'diffie-hellman-group14-sha256',
  'diffie-hellman-group16-sha512',
  'diffie-hellman-group18-sha512'
] %}

{{ stig_id }}-description:
  test.show_notification:
    - text: |
        --------------------------------------
        STIG Finding ID: V-248543
             The SSH daemon must allow only
             FIPS-validated key-exchange
             algorithms
        --------------------------------------

{%- if stig_id in skipIt %}
notify_{{ stig_id }}-skipSet:
  test.show_notification:
    - text: |
        Handler for {{ stig_id }} has been selected for skip.
{%- else %}
Set SSHD Key-Exchange Algorithms:
  file.replace:
    - name: '{{ cfgFile }}'
    - pattern: "^(|#)(CRYPTO_POLICY='.*)(-oKexAlgorithms=[a-z0-9,@.-]*)(.*$)"
    - repl: '\g<2>-oKexAlgorithms={{ fixOpts|join(',') }}\g<4>'
{%- endif %}
