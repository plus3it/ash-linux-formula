# Ref Doc:    STIG - Oracle Linux 8 v1r4
# Finding ID: V-248543
# Rule ID:    SV-248543r818608_rule
# STIG ID:    OL08-00-010159
# SRG ID:     SRG-OS-000120-GPOS-00061
#
# Finding Level: medium
#
# Rule Summary:
#       The OL8 operating system "pam_unix.so" module must be configured in
#       the system-auth file to use a FIPS 140-2 approved cryptographic
#       hashing algorithm for system authentication.
#
# References:
#   CCI:
#     - CCI-000803
#   NIST SP 800-53 :: IA-7
#   NIST SP 800-53A :: IA-7.1
#   NIST SP 800-53 Revision 4 :: IA-7
#
###########################################################################
{%- set stig_id = 'OL08-00-010159' %}
{%- set helperLoc = 'ash-linux/el8/STIGbyID/cat2/files' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}
{%- set targFile = '/etc/pam.d/system-auth' %}


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
file_{{ stig_id }}-{{ targFile }}:
  file.replace:
    - name: {{ targFile }}
    - pattern: '(^password\s*)(sufficient\s*)(.*)(pam_unix\.so)(.*)'
    - repl: '\1\2\3\4\5 sha512'
    - onlyif:
      - grep -q ORACLE_SUPPORT_PRODUCT /etc/os-release
      - grep -vP '^password\s*sufficient\s*.*pam_unix\.so.*sha512.*'
        {{ targFile }} | grep sha512
{%- endif %}
