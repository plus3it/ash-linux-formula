# Ref Doc:    STIG - RHEL 8 v1r7
# Finding ID: V-230326
# STIG ID:    RHEL-08-010780
# Rule ID:    SV-230484r627750_rule
# SRG ID:     SRG-OS-000480-GPOS-00227
#
# Finding Level: medium
#
# Rule Summary:
#	All local files and directories must have a valid owner.
#
# CCI-002165
#  - CCI-000366
#
# NIST SP 800-53 :: CM-6 b
# NIST SP 800-53A :: CM-6.1 (iv)
# NIST SP 800-53 Revision 4 :: CM-6 b
#
#################################################################
{%- set stig_id = 'RHEL-08-010780' %}
{%- set helperLoc = tpldir ~ '/files' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}
{%- set nouserFiles = [] %}
{%- set localFstypes = [
  'ext2',
  'ext3',
  'ext4',
  'xfs',
  'jfs',
  'btrfs',
] %}
{%- set mountData = salt.mount.fstab() %}
{%- set mounts = mountData.keys() %}

{{ stig_id }}-description:
  test.show_notification:
    - text: |
        --------------------------------------
        STIG Finding ID: V-230326
             All local files and directories
             must have a valid owner
        --------------------------------------

{%- if stig_id in skipIt %}
notify_{{ stig_id }}-skipSet:
  test.show_notification:
    - text: |
        Handler for {{ stig_id }} has been selected for skip.
{%- else %}
# Find files with no valid owner..
  {%- for mount in mounts %}
    {%- set mountType = mountData[mount]['fstype'] %}
    {%- if mountData[mount]['fstype'] in localFstypes %}
      {%- set foundString = salt.cmd.shell('find ' + mount + ' -xdev -nouser') %}
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
{%- endif %}
