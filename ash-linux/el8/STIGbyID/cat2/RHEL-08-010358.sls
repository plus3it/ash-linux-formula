# Ref Doc:    STIG - RHEL 8 v1r10
# Finding ID: V-256974
# Rule ID:    SV-256974r902755_rule
# STIG ID:    RHEL-08-010358
# SRG ID:     r902755_rule
#
# Finding Level: medium
#
# Rule Summary:
#       RHEL 8 must be configured to allow sending email notifications of
#       unauthorized configuration changes to designated personnel.
#
# References:
#   CCI:
#     - CCI-001744
#   NIST SP 800-53 Revision 4 :: CM-3 (5)
#
###########################################################################
{%- set stig_id = 'RHEL-08-010358' %}
{%- set helperLoc = tpldir ~ '/files' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}
{%- set mailRpms = [
  'mailx',
] %}

{{ stig_id }}-description:
  test.show_notification:
    - text: |
        --------------------------------------
        STIG Finding ID: V-256974
             OS must have mailer software
             available for notifiers to use
        --------------------------------------

{%- if stig_id in skipIt %}
notify_{{ stig_id }}-skipSet:
  cmd.run:
    - name: 'printf "\nchanged=no comment=''Handler for {{ stig_id }} has been selected for skip.''\n"'
    - stateful: True
    - cwd: /root
{%- else %}
# Ensure necessary mail-related RPMs are installed
package_{{ stig_id }}-MailRPMs:
  pkg.installed:
    - pkgs: {{ mailRpms }}
{%- endif %}
