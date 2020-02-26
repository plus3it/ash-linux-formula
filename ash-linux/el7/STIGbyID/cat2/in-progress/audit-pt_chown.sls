# Finding ID:	RHEL-07-030560
# Version:	RHEL-07-030560_rule
# SRG ID:	SRG-OS-000042-GPOS-00020
# Finding Level:	medium
# 
# Rule Summary:
#	All uses of the pt_chown command must be audited.
#
# CCI-000135 
# CCI-000172 
# CCI-002884 
#    NIST SP 800-53 :: AU-3 (1) 
#    NIST SP 800-53A :: AU-3 (1).1 (ii) 
#    NIST SP 800-53 Revision 4 :: AU-3 (1) 
#    NIST SP 800-53 :: AU-12 c 
#    NIST SP 800-53A :: AU-12.1 (iv) 
#    NIST SP 800-53 Revision 4 :: AU-12 c 
#    NIST SP 800-53 Revision 4 :: MA-4 (1) (a) 
#
#################################################################
{%- set stig_id = 'RHEL-07-030560' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat2/files' %}
{%- set ruleFile = '/etc/audit/rules.d/priv_acts.rules' %}
{%- set sysuserMax = salt['cmd.shell']("awk '/SYS_UID_MAX/{ IDVAL = $2 + 1} END { print IDVAL }' /etc/login.defs") %}
{%- set path2mon = '/usr/libexec/pt_chown' %}
{%- set key2mon = 'privileged-terminal' %}

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
    - repl: '-a always,exit -F path={{ path2mon }} -F perm=x -F auid>={{ sysuserMax }} -F auid!=4294967295 -F subj_role=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 -F key={{ key2mon }}'
    - append_if_not_found: True

