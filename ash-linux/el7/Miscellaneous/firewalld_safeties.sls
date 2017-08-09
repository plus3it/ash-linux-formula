# Summary:
#
#    This state acts as a safety-valve for hardening-actions that 
#    result in the firewalld zone being changed from 'public' to 
#    something more-restrictive (typically 'drop'). This state 
#    ensures that the firewalld service allows establishment of 
#    SSH-based connections and continuence of existing connections 
#    after a firewalld zone-change action.
#
#################################################################
{%- set ruleFile = '/etc/firewalld/direct.xml' %}

firewalld_file-{{ ruleFile }}:
  file.managed:
    - name: '{{ ruleFile }}'
    - contents: |-
        <?xml version="1.0" encoding="utf-8"?>
        <direct>
          <rule priority="10" table="filter" ipv="ipv4" chain="INPUT_direct">-m state --state RELATED,ESTABLISHED -m comment --comment 'Allow related and established connections' -j ACCEPT</rule>
          <rule priority="20" table="filter" ipv="ipv4" chain="INPUT_direct">-i lo -j ACCEPT</rule>
          <rule priority="30" table="filter" ipv="ipv4" chain="INPUT_direct">-d 127.0.0.0/8 '!' -i lo -j DROP</rule>
          <rule priority="50" table="filter" ipv="ipv4" chain="INPUT_direct">-p tcp -m tcp --dport 22 -j ACCEPT</rule>
        </direct>
    - user: 'root'
    - group: 'root'
    - mode: '0600'

svc_firewalld-safeties:
  service.running:
  - name: firewalld
  - reload: True
  - watch:
    - file: firewalld_file-{{ ruleFile }}
