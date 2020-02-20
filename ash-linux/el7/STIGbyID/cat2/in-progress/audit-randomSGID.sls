# Finding ID:	RHEL-07-030310
# Version:	RHEL-07-030310_rule
# SRG ID:	SRG-OS-000327-GPOS-00127
# Finding Level:	medium
# 
# Rule Summary:
#	All privileged function executions must be audited.
#
# CCI-002234 
#    NIST SP 800-53 Revision 4 :: AC-6 (9) 
#
#################################################################
{%- set stig_id = 'RHEL-07-030310' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat2/files' %}
{%- set ruleFile = '/etc/audit/rules.d/setuid_setgid.rules' %}
{%- set localFstypes = [
                         'ext2',
                         'ext3',
                         'ext4',
                         'xfs',
                         'jfs',
                         'btrfs'
                        ] %}
{%- set privFiles = [] %}
{%- set mntStruct = salt.mount.active() %}
{%- set mntList = mntStruct.keys() %}

script_{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stig_id }}.sh
    - cwd: /root

touch_{{ stig_id }}-{{ ruleFile }}:
  file.touch:
    - name: '{{ ruleFile }}'

{%- for mount in mntList %}
  {%- if mntStruct[mount]['fstype'] in localFstypes %}
    {%- set foundList = salt['cmd.shell']('find ' + mount + ' -xdev -type f \( -perm -4000 -o -perm -2000 \)').split('\n') %}
    {%- do privFiles.extend(foundList) %}
  {%- endif %}
{%- endfor %}

{%- for privFile in privFiles %}
  {%- if privFile %}
audit_{{ stig_id }}-{{ privFile }}:
  file.replace:
    - name: '{{ ruleFile }}'
    - pattern: '^.*{{ privFile }}.*$'
    - repl: '-a always,exit -F path={{ privFile }} -F auid>=1000 -F auid!=4294967295 -k setuid/setgid'
    - append_if_not_found: True
    - require:
      - file: touch_{{ stig_id }}-{{ ruleFile }}
  {%- endif %}
{%- endfor %}
