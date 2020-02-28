# STIG ID:	RHEL-07-030200
# Rule ID:	SV-95727r1_rule
# Vuln ID:	V-81015
# SRG ID:	SRG-OS-000342-GPOS-00133
#               SRG-OS-000479-GPOS-00224
# Finding Level:	medium
# 
# Rule Summary:
#       The operating system must be configured to use the au-remote plugin.
#
# CCI-001851 
#    NIST SP 800-53 Revision 4 :: AU-4 (1) 
#
#################################################################
{%- set stig_id = 'RHEL-07-030200' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat2/files' %}
{%- set remoteCfg = '/etc/audisp/plugins.d/au-remote.conf' %}
{%- set audSrv = salt.pillar.get('ash-linux:lookup:audisp-use-remote', 'yes') %}

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
file_{{ stig_id }}-{{ remoteCfg }}:
  file.replace:
    - name: '{{ remoteCfg }}'
    - pattern: ^[\s]*active[\s]*=[\s]*.*$
    - repl: 'active = {{ audSrv }}'
    - append_if_not_found: True
{%- else %}
file_{{ stig_id }}-{{ remoteCfg }}:
  file.append:
    - name: '{{ remoteCfg }}'
    - text: 'active = {{ audSrv }}'
    - makedirs: True
{%- endif %}
