# Ref Doc:    STIG - RHEL 8 v1r10
# Finding ID: V-230532
# Rule ID:    SV-230532r627750_rule
# STIG ID:    RHEL-08-040180
# SRG ID:     <none>
#
# Finding Level: medium
#
# Rule Summary:
#       The debug-shell systemd service must be disabled.
#
# References:
#   CCI:
#     - CCI-000366
#   NIST SP 800-53 :: CM-6 b
#   NIST SP 800-53A :: CM-6.1 (iv)
#   NIST SP 800-53 Revision 4 :: CM-6 b
#
###########################################################################
{%- set stig_id = 'RHEL-08-040180' %}
{%- set helperLoc = 'ash-linux/el8/STIGbyID/cat2/files' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}

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
mask debug-shell service:
  service.masked:
    - name: "debug-shell.service"
    - runtime: True
{%- endif %}
