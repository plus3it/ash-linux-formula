# Ref Doc:    STIG - RHEL 7 v3r11
# Finding ID: V-250314
# Rule ID:    SV-250314r877392_rule
# STIG ID:    RHEL-07-020023
# SRG ID:     SRG-OS-000324-GPOS-00125
#
# Finding Level: medium
#
# Rule Summary:
#       The operating system must elevate the SELinux context when an
#       administrator calls the sudo command
#
# References:
#   CCI:
#     - CCI-002165
#       - NIST SP 800-53 Revision 4 :: AC-3 (4)
#     - CCI-002235
#       - NIST SP 800-53 Revision 4 :: AC-6 (10)
#
###########################################################################
{%- set stig_id = 'RHEL-07-020023' %}
{%- set helperLoc = 'ash-linux/el8/STIGbyID/cat2/files' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}
{%- set sudoerFiles = [ '/etc/sudoers' ] %}
{%- for moreSudoerFiles in salt.file.find('/etc/sudoers.d', type='f', grep='^%') %}
  {%- do sudoerFiles.append(moreSudoerFiles) %}
{%- endfor %}

{%- if stig_id in skipIt %}
notify_{{ stig_id }}-skipSet:
  cmd.run:
    - name: 'printf "\nchanged=no comment=''Handler for {{ stig_id }} has been selected for skip.''\n"'
    - stateful: True
    - cwd: /root
{%- else %}
  {%- for checkFile in sudoerFiles %}
Fixing {{ checkFile }} (per {{ stig_id }}):
  file.replace:
    - name: '{{ checkFile }}'
    - append_if_not_found: False
    - backup: False
    - pattern: '^%([a-z0-9]*)(\s+)([A-Z]*)=([/(][A-Za-z]*[)])\s+(?!(TYPE|ROLE)=[a-z_]*)\s*([A-Za-z:]*)$'
    - repl: '%\1\2\3=\4 TYPE=sysadm_t ROLE=sysadm_r \6'
  {%- endfor %}
{%- endif %}
