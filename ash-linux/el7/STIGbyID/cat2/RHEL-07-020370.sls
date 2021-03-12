# Finding ID:	RHEL-07-020370
# Version:	RHEL-07-020370_rule
# SRG ID:	SRG-OS-000480-GPOS-00227
# Finding Level:	medium
#
# Rule Summary:
#	All files and directories must have a valid group owner.
#
# CCI-002165
#    NIST SP 800-53 Revision 4 :: AC-3 (4)
#
#################################################################
{%- set stig_id = 'RHEL-07-020370' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat2/files' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}
{%- set nogroupFiles = [] %}
{%- set localFstypes = [
                         'ext2',
                         'ext3',
                         'ext4',
                         'xfs',
                         'jfs',
                         'btrfs'
                        ] %}
{%- set mountData = salt.mount.fstab() %}
{%- set mounts = mountData.keys() %}

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
# Find files with no valid owner..
  {%- for mount in mounts %}
    {%- set mountType = mountData[mount]['fstype'] %}
    {%- if mountData[mount]['fstype'] in localFstypes %}
      {%- set foundString = salt['cmd.shell']('find ' + mount + ' -xdev -nogroup') %}
      {%- set foundList = foundString.split('\n') %}
      {%- do nogroupFiles.extend(foundList) %}
    {%- endif %}
  {%- endfor %}

# Take ownership of files
  {%- if nogroupFiles %}
    {%- for file in nogroupFiles %}
      {%- if file %}
file_{{ stig_id }}-{{ file }}:
  file.managed:
    - name: '{{ file }}'
    - group: 'root'
      {%- endif %}
    {%- endfor %}
  {%- endif %}
{%- endif %}
