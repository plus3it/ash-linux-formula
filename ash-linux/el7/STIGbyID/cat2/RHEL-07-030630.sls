# Finding ID:	RHEL-07-030630
# Version:	RHEL-07-030630_rule
# SRG ID:	SRG-OS-000471-GPOS-00215
# Finding Level:	medium
# 
# Rule Summary:
#	All uses of the pam_timestamp_check command must be audited.
#
# CCI-000172 
#    NIST SP 800-53 :: AU-12 c 
#    NIST SP 800-53A :: AU-12.1 (iv) 
#    NIST SP 800-53 Revision 4 :: AU-12 c 
#
#################################################################
{%- set stig_id = 'RHEL-07-030630' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat2/files' %}
{%- set ruleFile = '/etc/audit/rules.d/priv_acts.rules' %}
{%- set sysuserMax = salt['cmd.shell']("awk '/SYS_UID_MAX/{print $2}' /etc/login.defs") %}
{%- set path2mon = '/sbin/pam_timestamp_check' %}
{%- set key2mon = 'privileged-pam' %}

script_{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stig_id }}.sh
    - cwd: /root

{%- if not salt.file.file_exists(ruleFile) %}
touch_{{ stig_id }}-{{ ruleFile }}:
  file.touch:
    - name: '{{ ruleFile }}'
{%- endif %}

file_{{ stig_id }}-{{ ruleFile }}:
  file.replace:
    - name: '{{ ruleFile }}'
    - pattern: '^-a always,exit -F path={{ path2mon }}.*$'
    - repl: '-a always,exit -F path={{ path2mon }} -F perm=x -F auid>{{ sysuserMax }} -F auid!=4294967295 -F subj_role=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 -F key={{ key2mon }}'
    - append_if_not_found: True

