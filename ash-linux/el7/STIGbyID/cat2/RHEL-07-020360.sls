# Finding ID:	RHEL-07-020360
# Version:	RHEL-07-020360_rule
# SRG ID:	SRG-OS-000480-GPOS-00227
# Finding Level:	medium
# 
# Rule Summary:
#	All files and directories must have a valid owner.
#
# CCI-002165 
#    NIST SP 800-53 Revision 4 :: AC-3 (4) 
#
#################################################################
{%- set stig_id = 'RHEL-07-020360' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat2/files' %}
{%- set nouserFiles = [] %}
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

# Find files with no valid owner..
{%- for mount in mounts %}
  {%- set mountType = mountData[mount]['fstype'] %}
  {%- if mountData[mount]['fstype'] in localFstypes %}
    {%- set foundString = salt['cmd.shell']('find ' + mount + ' -xdev -nouser') %}
    {%- set foundList = foundString.split('\n') %}
    {%- do nouserFiles.extend(foundList) %}
  {%- endif %}
{%- endfor %}

# Take ownership of files
{%- if nouserFiles %}
  {%- for file in nouserFiles %}
    {%- if file %}
file_{{ stig_id }}-{{ file }}:
  file.managed:
    - name: '{{ file }}'
    - user: 'root'
    {%- endif %}
  {%- endfor %}
{%- endif %}
