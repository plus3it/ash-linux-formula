# Ref Doc:    STIG - RHEL 7 v3r11
# Finding ID: V-204587
# Rule ID:    SV-204587r861072_rule
# STIG ID:    RHEL-07-040320
# SRG ID:     SRG-OS-000163-GPOS-00072
#
# Finding Level: medium
#
# Rule Summary:
#       The Red Hat Enterprise Linux operating system must be configured
#       so that all network connections associated with SSH traffic are
#       terminated at the end of the session or after 10 minutes of
#       inactivity, except to fulfill documented and validated mission
#       requirements.
#
# References:
#   CCI:
#     - CCI-001133
#       - NIST SP 800-53 :: SC-10
#       - NIST SP 800-53A :: SC-10.1 (ii)
#       - NIST SP 800-53 Revision 4 :: SC-10
#     - CCI-002361
#       - NIST SP 800-53 Revision 4 :: AC-12
#
###########################################################################
{%- set stig_id = 'RHEL-07-040320' %}
{%- set helperLoc = 'ash-linux/el8/STIGbyID/cat2/files' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}
{%- set cfgFile = '/etc/ssh/sshd_config' %}
{%- set cfgItemName = 'ClientAliveInterval' %}
{%- set cfgItemValu = '600' %}

script_{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stig_id }}.sh
    - cwd: /root
    - stateful: False

{%- if stig_id in skipIt %}
notify_{{ stig_id }}-skipSet:
  cmd.run:
    - name: 'printf "\nchanged=no comment=''Handler for {{ stig_id }} has been selected for skip.''\n"'
    - stateful: True
    - cwd: /root
{%- else %}
include:
  - ash-linux.el7.STIGbyID.cat2.restart_sshd

Fix {{cfgItemName }} in {{ cfgFile }} - {{ stig_id }}:
  file.replace:
    - name: '{{ cfgFile }}'
    - append_if_not_found: True
    - not_found_content: |-
        # Inserted per STIG {{ stig_id }}
        {{ cfgItemName }} {{ cfgItemValu }}
    - onchanges_in:
      - service: service_sshd_restart
    - onlyif:
      - fun: pkg.version
        args:
          - openssh-server
    - pattern: '^(#|\s*)\s*{{ cfgItemName }}.*$'
    - repl: '{{ cfgItemName }} {{ cfgItemValu }}'
{%- endif %}
