# Finding ID:	RHEL-07-030674
# Version:	RHEL-07-030674_rule
# SRG ID:	SRG-OS-000471-GPOS-00216
# Finding Level:	medium
# 
# Rule Summary:
#	All uses of the modprobe command must be audited.
#
# CCI-000172 
#    NIST SP 800-53 :: AU-12 c 
#    NIST SP 800-53A :: AU-12.1 (iv) 
#    NIST SP 800-53 Revision 4 :: AU-12 c 
#
#################################################################
{%- set stig_id = 'RHEL-07-030674' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat2/files' %}
{%- set ruleFile = '/etc/audit/rules.d/audit.rules' %}
{%- set path2mon = '/sbin/modprobe' %}
{%- set key2mon = 'module-change' %}

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
    - pattern: '^-w {{ path2mon }}.*$'
    - repl: '-w {{ path2mon }} -F perm=x -F auid!=4294967295 -F subj_role=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 -F key={{ key2mon }}'
    - append_if_not_found: True

