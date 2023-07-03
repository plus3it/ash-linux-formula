# Ref Doc:    STIG - RHEL 8 v1r10
# Finding ID: V-230238
# Rule ID:    SV-230504r854047_rule
# STIG ID:    RHEL-08-040090
# SRG ID:     SRG-OS-000297-GPOS-00115
#
# Finding Level: medium
#
# Rule Summary:
#       The operating system must enable a firewall service that  employs
#       a deny-all, allow-by-exception policy for allowing connections to
#       other systems.
#
# References:
#   CCI:
#     - CCI-002314
#   NIST SP 800-53 Revision 4 :: AC-17 (1)
#
###########################################################################
{%- set stig_id = 'RHEL-08-040090' %}
{%- set helperLoc = 'ash-linux/el8/STIGbyID/cat2/files' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}
{%- set firewalldConf = '/etc/firewalld/firewalld.conf' %}
{%- set firewalldParm = 'DefaultZone' %}
{%- set firewalldValu = salt.pillar.get('ash-linux:lookup:def_firewall_zone', 'drop') %}
{%- set firewalldSafePorts = salt.pillar.get('ash-linux:lookup:def_firewall_ports', [] ) %}
{%- set firewalldSafeSvcs = salt.pillar.get('ash-linux:lookup:def_firewall_services', [ 'ssh', ] ) %}

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
Set Default firewalld zone - config-file:
  file.replace:
    - name: '{{ firewalldConf }}'
    - pattern: '^({{ firewalldParm }})(\s*=\s*).*'
    - repl: '\1=drop'
    - append_if_not_found: True
    - not_found_content: |-
        # Inserted per STIG {{ stig_id }}
        {{ firewalldParm }}={{ firewalldValu }}

Set Default firewalld zone - config-running:
  module.run:
    - name: firewalld.set_default_zone
    - onchanges:
      - file: 'Set Default firewalld zone - config-file'
    - unless:
      - '[[ $( firewall-cmd --get-default-zone ) == "drop" ]]'
    - zone: drop

Set Minimum Ports:
  firewalld.present:
    - name: '{{ firewalldValu }}'
    - onchanges:
      - module: 'Set Default firewalld zone - config-running'
    - ports: {{ firewalldSafePorts }}
    - prune_ports: False
    - prune_services: False
    - services: {{ firewalldSafeSvcs }}
{%- endif %}
