# Ref Doc:    STIG - RHEL 8 v1r9
# Finding ID: V-230486
# Rule ID:    SV-230486r627750_rule
# STIG ID:    RHEL-08-030742
# SRG ID:     SRG-OS-000095-GPOS-00049
#
# Finding Level: low
#
# Rule Summary:
#       The OS must disable network management of the chrony daemon.
#
# References:
#   CCI:
#     - CCI-000381
#   NIST SP 800-53 :: CM-7
#   NIST SP 800-53A :: CM-7.1 (ii)
#   NIST SP 800-53 Revision 4 :: CM-7 a
#
###########################################################################
{%- set stig_id = 'RHEL-08-030742' %}
{%- set helperLoc = 'ash-linux/el8/STIGbyID/cat3/files' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}
{%- set targFile = '/etc/chrony.conf' %}

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
file_{{ stig_id }}-{{ targFile }}:
  file.replace:
    - name: '{{ targFile }}'
    - append_if_not_found: True
    - not_found_content: |

        # Insert per {{ stig_id }} - disable network management of the chrony daemon
        cmdport 0
    - onlyif:
      - '[[ $( rpm -q --quiet chrony )$? -eq 0 ]]'
      - '[[ -e {{ targFile }} ]]'
    - pattern: '^\s*cmdport\s.*$'
    - repl: 'cmdport 0'
{%- endif %}
