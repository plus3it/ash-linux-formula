# Finding ID:	RHEL-07-021012
# Version:	RHEL-07-021012_rule
# SRG ID:	SRG-OS-000480-GPOS-00227
# Finding Level:	medium
#
# Rule Summary:
#	Files systems that are being imported via Network File System
#	(NFS) must be mounted to prevent files with the setuid and
#	setgid bit set from being executed.
#
# CCI-000366
#    NIST SP 800-53 :: CM-6 b
#    NIST SP 800-53A :: CM-6.1 (iv)
#    NIST SP 800-53 Revision 4 :: CM-6 b
#
#################################################################
{%- set stig_id = 'RHEL-07-021012' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat2/files' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}
{%- set fstabMntStream = salt.mount.fstab() %}
{%- set fstabMntList = fstabMntStream.keys() %}


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
  {%- for mount in fstabMntList %}
    {%- set fstabMountStruct = fstabMntStream[mount] %}
    {%- set fstabDevice = fstabMountStruct['device'] %}
    {%- set fstabDump = fstabMountStruct['dump'] %}
    {%- set fstabFstype = fstabMountStruct['fstype'] %}
    {%- set fstabOpts = fstabMountStruct['opts'] %}
    {%- set fstabPass = fstabMountStruct['pass'] %}
    {%- set optSstring = fstabMountStruct['opts']|join(' ') + ',nosuid' %}

    {%- if 'nfs' in fstabFstype and
      not 'nosuid' in fstabOpts %}
fix_{{ stig_id }}-{{ mount }}:
  module.run:
    - name: 'mount.set_fstab'
    - m_name: '{{ mount }}'
    - device: '{{ fstabDevice }}'
    - fstype: '{{ fstabFstype }}'
    - opts: '{{ optSstring }}'
    - dump: '{{ fstabDump }}'
    - pass_num: '{{ fstabPass }}'
    {%- endif %}
  {%- endfor %}
{%- endif %}

## /var/log/audit:
##     ----------
##     device:
##         /dev/mapper/VolGroup00-auditVol
##     dump:
##         0
##     fstype:
##         ext4
##     opts:
##         - defaults
##     pass:
##         0

