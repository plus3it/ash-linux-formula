# Ref Doc:    STIG - RHEL 8 v1r7
# Finding ID: V-245540
# Rule ID:    SV-245540r754730_rule
# STIG ID:    RHEL-08-010001
# SRG ID:     SRG-OS-000191-GPOS-00080
#
# Finding Level: medium
#
# Rule Summary:
#       The EL8 operating system must implement the Endpoint Security
#       for Linux Threat Prevention tool.
#
# References:
#   CCI:
#     - CCI-001233
#   NIST SP 800-53 :: SI-2 (2)
#   NIST SP 800-53A :: SI-2 (2).1 (ii)
#   NIST SP 800-53 Revision 4 :: SI-2 (2)
#
###########################################################################
{%- set stig_id = 'RHEL-08-010001' %}
{%- set helperLoc = 'ash-linux/el8/STIGbyID/cat2/files' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}
{%- set targFile = '/etc/security/faillock.conf' %}

script_{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stig_id }}.sh
    - cwd: /root
    - stateful: True

{%- if stig_id in skipIt %}
notify_{{ stig_id }}-skipSet:
  cmd.run:
    - name: 'printf "\nchanged=no comment=''Handler for {{ stig_id }} has been selected for skip.''\n"'
    - stateful: True
    - cwd: /root
{%- else %}
Print RHEL-08-010001 help:
  test.show_notification:
    - text: |
        Installing/configuring VSEL is outside the scope of a generic
        hardening-project such as this one. This handler is here as a place-
        holder. The exception will also be included in the project's FAQ
        of known/expected post-hardening findings.
{%- endif %}
