# Ref Doc:    STIG - RHEL 8 v1r9
# Finding ID: V-230550
# Rule ID:    SV-230550r627750_rule
# STIG ID:    RHEL-08-040290
# SRG ID:     SRG-OS-000480-GPOS-00227
#
# Finding Level: medium
#
# Rule Summary:
#       The OS must be configured to prevent unrestricted mail relaying
#
# References:
#   CCI:
#     - CCI-000366
#   NIST SP 800-53 :: CM-6 b
#   NIST SP 800-53A :: CM-6.1 (iv)
#   NIST SP 800-53 Revision 4 :: CM-6 b
#
###########################################################################
{%- set stig_id = 'RHEL-08-040290' %}
{%- set helperLoc = tpldir ~ '/files' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}

{{ stig_id }}-description:
  test.show_notification:
    - text: |
        --------------------------------------
        STIG Finding ID: V-230550
             OS must be configured to prevent
             unrestricted mail relaying
        --------------------------------------

{%- if stig_id in skipIt %}
notify_{{ stig_id }}-skipSet:
  cmd.run:
    - name: 'printf "\nchanged=no comment=''Handler for {{ stig_id }} has been selected for skip.''\n"'
    - stateful: True
    - cwd: /root
{%- else %}
Prevent Unrestricted Mail Relaying:
  module.run:
    - name: postfix.set_main
    - onlyif:
      - fun: pkg.version
        args:
          - postfix
    - key: smtpd_client_restrictions
    - value: permit_mynetworks, reject

Insert {{ stig_id }} comment:
  file.replace:
    - name: '/etc/postfix/main.cf'
    - ignore_if_missing: True
    - pattern: '(^\s*smtpd_client_restrictions.*$)'
    - repl: '\n# smtpd_client_restrictions setting required per {{ stig_id }}\n\1'
    - require:
      - module: 'Prevent Unrestricted Mail Relaying'
    - unless:
      - '[[ $( grep -q "^# smtpd_client_restrictions setting required per {{ stig_id }}" /etc/postfix/main.cf )$? -eq 0 ]]'
{%- endif %}
