# Finding ID:	RHEL-07-040320
# Version:	RHEL-07-040320_rule
# SRG ID:	SRG-OS-000480-GPOS-00227
# Finding Level:	low
#
# Rule Summary:
#	"For systems using DNS resolution, at least two name servers must be configured."
#
# CCI-000366
#    NIST SP 800-53 :: CM-6 b
#    NIST SP 800-53A :: CM-6.1 (iv)
#    NIST SP 800-53 Revision 4 :: CM-6 b
#
#################################################################
{%- set stig_id = 'RHEL-07-040320' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat3/files' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}
{%- set nsswitchConf = '/etc/nsswitch.conf' %}
{%- set resolvConf = '/etc/resolv.conf' %}
{%- set dnsList = salt['cmd.shell']("awk '/^nameserver/ {print $2}' " + resolvConf).split('\n') %}
{%- set dnsList_add = salt.pillar.get('ash-linux:lookup:dns-info:nameservers', []) %}

script_{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stig_id }}.sh
    - cwd: /root

{%- if stig_id in skipIt %}
{%- elif ( salt.file.search(nsswitchConf, '^hosts.*dns') ) %}
notice_{{ stig_id }}-{{ nsswitchConf }}:
  cmd.run:
    - name: 'printf "\nchanged=no comment=''System uses DNS for host-resolution''\n"'
    - cwd: /root
    - stateful: True
  {%- if dnsList|length < 2 %}
    {%- for chkDns in dnsList_add %}
      {%- if not chkDns in dnsList %}
        {%- do dnsList.append(chkDns) %}
      {%- endif %}
    {%- endfor %}
    {%- if dnsList|length < 2 %}
nameserver_{{ stig_id }}-count:
  cmd.run:
    - name: 'printf "\nchanged=no comment=''Found less than two namserver entries in {{ resolvConf }}: this may be a finding.''\n"'
    - cwd: /root
    - stateful: True
    {%- else %}
      {%- for dnsIp in dnsList %}
nameserver_{{ stig_id }}-{{ dnsIp }}:
  file.append:
    - name: '{{ resolvConf }}'
    - text: 'nameserver {{ dnsIp }}'
      {%- endfor %}
    {%- endif %}
  {%- else %}
nameserver_{{ stig_id }}-count:
  cmd.run:
    - name: 'printf "\nchanged=no comment=''Found {{ dnsList|length }} namserver entries in {{ resolvConf }}: state ok.''\n"'
    - cwd: /root
    - stateful: True
  {%- endif %}
{%- endif %}
