# Finding ID:   RHEL-07-040560
# Version:      RHEL-07-040560_rule
# SRG ID:       SRG-OS-000480-GPOS-00227
# Finding Level:        medium
#
# Rule Summary:
#       An X Windows display manager must not be installed unless approved.
#
# CCI-000366
#    NIST SP 800-53 :: CM-6 b
#    NIST SP 800-53A :: CM-6.1 (iv)
#    NIST SP 800-53 Revision 4 :: CM-6 b
#
#################################################################
{%- set stig_id = 'RHEL-07-040560' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat2/files' %}
{%- set hazGroupMeta = salt.pkg.group_list()['available'] %}
{%- set targRpm = "xorg-x11-server-common" %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}
script_{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stig_id }}.sh
    - cwd: /root
{%- if stig_id in skipIt %}
notify_{{ stig_id }}-skipSet:
  cmd.run:
    - name: 'printf "\nchanged=no comment=''Handler for {{ stig_id }} has been selected for skip.''\n"'
    - cwd: /root
    - stateful: True
{%- else %}
purge_{{ stig_id }}-{{ targRpm }}:
  pkg.removed:
    - pkgs:
      - '{{ targRpm }}'
  {%- if hazGroupMeta and 'X Window System' in hazGroupMeta %}
    {%- for rpm in salt.pkg.group_info('X Window System') %}
      - '{{ rpm }}'
    {%- endfor %}
  {%- endif %}
{%- endif %}
