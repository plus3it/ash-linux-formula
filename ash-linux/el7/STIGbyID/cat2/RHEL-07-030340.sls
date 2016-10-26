# Finding ID:	RHEL-07-030340
# Version:	RHEL-07-030340_rule
# SRG ID:	SRG-OS-000342-GPOS-00133
# Finding Level:	medium
# 
# Rule Summary:
#	The audit system must take appropriate action when the audit
#	storage volume is full.
#
# CCI-001851 
#    NIST SP 800-53 Revision 4 :: AU-4 (1) 
#
#################################################################
{%- set stig_id = 'RHEL-07-030340' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat2/files' %}
{%- set remoteCfg = '/etc/audisp/audisp-remote.conf' %}
{%- set nfParm = 'network_failure_action'%}
{%- set dfParm = 'disk_full_action'%}
{%- set aurmtNetFail = salt.pillar.get('ash-linux:lookup:audisp-net-fail', 'syslog') %}
{%- set auDiskFull = salt.pillar.get('ash-linux:lookup:audisp-disk-full', 'syslog') %}

script_{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stig_id }}.sh
    - cwd: /root

# STIG doesn't enumerate this, but the handler's kinda pointless
# if this package isn't installed
pkg_{{ stig_id }}-audispRemote:
  pkg.installed:
    - name: audispd-plugins

{%- if salt.file.file_exists(remoteCfg) %}
file_{{ stig_id }}-{{ nfParm }}:
  file.replace:
    - name: '{{ remoteCfg }}'
    - pattern: '^\s{{ nfParm }}.*$'
    - repl: '{{ nfParm }} = {{ aurmtNetFail }}'
    - append_if_not_found: True

file_{{ stig_id }}-{{ dfParm }}:
  file.replace:
    - name: '{{ remoteCfg }}'
    - pattern: '^\s{{ dfParm }}.*$'
    - repl: '{{ dfParm }} = {{ auDiskFull }}'
    - append_if_not_found: True
{%- else %}
file_{{ stig_id }}-{{ nfParm }}:
  file.append:
    - name: '{{ remoteCfg }}'
    - text: '{{ nfParm }} = {{ aurmtNetFail }}'
    - makedirs: True

file_{{ stig_id }}-{{ dfParm }}:
  file.append:
    - name: '{{ remoteCfg }}'
    - text: '{{ dfParm }} = {{ auDiskFull }}'
    - makedirs: True
{%- endif %}
