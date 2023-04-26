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
{%- set helperLoc = 'ash-linux/el8/STIGbyID/cat2/files' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}
{%- set clientRestrictStrn = '' %}
{%- if 'postfix' in salt.pkg.list_pkgs() %}
  {%- set clientRestrictDict = salt.postfix.show_main() %}
  {%- if 'smtpd_client_restrictions' in clientRestrictDict %}
    {%- set clientRestrictStrn = salt.postfix.show_main()['smtpd_client_restrictions'] %}
  {%- endif %}
{%- endif %}

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
Check Postfix:
  pkg.installed:
    - name: 'postfix'
    - test: True

  {%- if ( clientRestrictStrn == 'permit_mynetworks,reject' or clientRestrictStrn == 'permit_mynetworks, reject' ) %}
Mail-Relaying Status:
  cmd.run:
    - cwd: /root
    - name: 'printf "\nchanged=no comment=''Mail-Relaying Already Restricted''\n"'
    - stateful: True
  {%- else %}
Prevent Unrestricted Mail Relaying:
  module.run:
    - name: 'postfix.set_main'
    - key: 'smtpd_client_restrictions'
    - value: 'permit_mynetworks, reject'
    - require:
      - pkg: 'Check Postfix'
  {%- endif %}
{%- endif %}
