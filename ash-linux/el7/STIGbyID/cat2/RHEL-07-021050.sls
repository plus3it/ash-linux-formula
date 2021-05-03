# Finding ID:	RHEL-07-021050
# Version:	RHEL-07-021050_rule
# SRG ID:	SRG-OS-000480-GPOS-00227
# Finding Level:	medium
#
# Rule Summary:
#	All world-writable directories must be group-owned by root, sys,
#	bin, or an application group.
#
# CCI-000366
#    NIST SP 800-53 :: CM-6 b
#    NIST SP 800-53A :: CM-6.1 (iv)
#    NIST SP 800-53 Revision 4 :: CM-6 b
#
#################################################################
{%- set stig_id = 'RHEL-07-021050' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat2/files' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}
{%- set globWrDirs = salt['cmd.shell']('find / -path /proc -prune -o -perm /002 -type d -print').split('\n') %}
{%- set okUsers = [
                   'root',
                   'sys',
                   'bin'
                    ] %}

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
  {%- for globWrDir in globWrDirs %}
    {%- set wrDirOwn = salt['cmd.shell']('stat -c %G ' + globWrDir) %}
    {%- if not wrDirOwn in okUsers %}
fix_{{ stig_id }}-{{ globWrDir }}:
  file.directory:
    - name: '{{ globWrDir }}'
    - group: 'root'
    {%- endif %}
  {%- endfor %}
{%- endif %}
