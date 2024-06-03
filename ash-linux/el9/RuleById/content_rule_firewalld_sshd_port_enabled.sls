# Rule ID:              content_rule_firewalld_sshd_port_enabled
# Finding Level:        medium
#
# Rule Summary:
#       If the SSH server is in use, inbound connections to SSH's port should be
#       allowed to permit remote access through SSH. In more restrictive
#       firewalld settings, the SSH port should be added to the proper firewalld
#       zone in order to allow SSH remote access.
#
# Identifiers:
#   - content_rule_firewalld_sshd_port_enabled
#
# References:
#   - CUI
#     - 3.1.12
#   - ISM
#     - 1416
#   - NIST
#     - AC-17(a)
#     - CM-6(b)
#     - CM-7(a)
#     - CM-7(b)
#   - OS-SRG
#     - SRG-OS-000096-GPOS-00050
#
################################################################################
{%- set stig_id = 'firewalld_sshd_port_enabled' %}
{%- set helperLoc = tpldir ~ '/files' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}
{%- set nicList =  salt.network.interfaces() %}
{%- set allZones = salt.firewalld.get_zones() %}
{%- set targZone = salt.pillar.get('ash-linux:lookup:stig-interface-zone', 'drop') %}
{%- set nmcliFiles = [
    '/run/NetworkManager',
    '/etc/NetworkManager',
    '/usr/lib/NetworkManager'
  ]
%}

{{ stig_id }}-description:
  test.show_notification:
    - text: |
        --------------------------------------
        STIG Finding ID: {{ stig_id }}
             Allow SSHD access through the
             host-based firewall
        --------------------------------------

{%- if stig_id in skipIt %}
notify_{{ stig_id }}-skipSet:
  test.show_notification:
    - text: |
        Handler for {{ stig_id }} has been selected for skip.
{%- else %}
  {%- for zone in allZones %}
Enable SSHD for {{ zone }} zone:
  module.run:
    - name: firewalld.add_service
    - onlyif:
      - fun: pkg.version
        args:
          - firewalld
    - permanent: True
    - require_in:
      - module: Enable SSHD globally
    - service: ssh
    - unless:
      - '[[ $( firewall-cmd --list-services --zone {{ zone }} --permanent ) == *"ssh"* ]]'
    - zone: {{ zone }}
  {%- endfor %}

Enable SSHD globally:
  module.run:
    - name: firewalld.add_service
    - permanent: True
    - service: ssh
    - unless:
      - '[[ $( firewall-cmd --list-services ) == *"ssh"* ]]'

  {%- for nic in nicList %}
    {%- if not nic == 'lo' %}
Convert to keyfile format for {{ nic }}:
  cmd.run:
    - name: 'nmcli connection migrate'
    - unless:
      - grep -q {{ nic }}$ {{ nmcliFiles | join('/system-connections/* ')}}
Set Zone for {{ nic }}:
  module.run:
    - name: firewalld.add_interface
    - interface: {{ nic }}
    - require:
      - module: Enable SSHD globally
    - permanent: True
    - unless:
      - '[[ $( firewall-cmd --get-zone-of-interface {{ nic }} ) == "{{ targZone }}" ]]'
    - zone: {{ targZone }}
    {%- endif %}
  {%- endfor %}
{%- endif %}
