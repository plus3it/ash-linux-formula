# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38653
# Finding ID:	V-38653
# Version:	RHEL-06-000341
# Finding Level:	High
#
#     The snmpd service must not use a default password. Presence of the 
#     default SNMP password enables querying of different system aspects 
#     and could result in unauthorized knowledge of the system.
#
############################################################

{%- set stigId = 'V38653' %}
{%- set helperLoc = 'ash-linux/el6/STIGbyID/cat1/files' %}
{%- set chkFile = '/etc/snmp/snmpd.conf' %}
{%- set pkgName = 'net-snmp' %}

script_{{ stigId }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stigId }}.sh
    - cwd: /root

{%- if salt.pkg.version(pkgName) %}
file_{{ stigId }}-snmpd:
  file.comment:
    - name: '{{ chkFile }}'
    - regex: ^[a-z].* public
    - char: '## '
    - unless: 'grep -v "^#" {{ chkFile }} | grep public'
{%- else %}
file_{{ stigId }}-snmpd:
  cmd.run:
    - name: 'echo "No relevant findings possible: the ''{{ pkgName }}'' package is not installed"'
{%- endif %}
