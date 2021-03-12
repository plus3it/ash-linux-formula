# STIG ID:	RHEL-07-030300
# Rule ID:	SV-86707r2_rule
# Vuln ID:	V-72083
# SRG ID:	SRG-OS-000342-GPOS-00133
# Finding Level:	medium
#
# Rule Summary:
#	The operating system must off-load audit records onto a different
#	system or media from the system being audited.
#
# CCI-001851
#    NIST SP 800-53 Revision 4 :: AU-4 (1)
#
#################################################################
{%- set stig_id = 'RHEL-07-030300' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat2/files' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}
{%- set remoteCfg = '/etc/audisp/audisp-remote.conf' %}
{%- set audSrv = salt.pillar.get('ash-linux:lookup:audisp-server', '') %}
{%- set outpt = '/usr/bin/printf'%}

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
# STIG doesn't enumerate this, but the handler's kinda pointless
# if this package isn't installed
pkg_{{ stig_id }}-audispRemote:
  pkg.installed:
    - name: audispd-plugins

  {%- if audSrv %}
    {%- if salt.file.file_exists(remoteCfg) %}
file_{{ stig_id }}-{{ remoteCfg }}:
  file.replace:
    - name: '{{ remoteCfg }}'
    - pattern: '^\sremote_server.*$'
    - repl: 'remote_server = {{ audSrv }}'
    - append_if_not_found: True
    {%- else %}
file_{{ stig_id }}-{{ remoteCfg }}:
  file.append:
    - name: '{{ remoteCfg }}'
    - text: 'remote_server = {{ audSrv }}'
    - makedirs: True
    {%- endif %}
  {%- else %}
file_{{ stig_id }}-{{ remoteCfg }}:
  cmd.run:
    - name: '{{ outpt }} "\nchanged=no comment=''ALERT: No remote audit-server is defined''\n"'
    - cwd: /root
    - stateful: True
  {%- endif %}
{%- endif %}
