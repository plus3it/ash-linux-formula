# Finding ID:	RHEL-07-021011
# Version:	RHEL-07-021011_rule
# SRG ID:	SRG-OS-000480-GPOS-00227
# Finding Level:	medium
#
# Rule Summary:
#	Files systems that are used with removable media must be
#	mounted to prevent files with the setuid and setgid bit set
#	from being executed.
#
# CCI-000366
#    NIST SP 800-53 :: CM-6 b
#    NIST SP 800-53A :: CM-6.1 (iv)
#    NIST SP 800-53 Revision 4 :: CM-6 b
#
#################################################################
{%- set stig_id = 'RHEL-07-021011' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat2/files' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}
{%- set fstabMnts = salt.mount.fstab() %}
{%- set wantOpt = 'nosuid' %}
{%- set mediaFStypes = [
                        'iso9660',
                        'ntfs',
                        'udf',
                        'msdos',
                        'fat',
                        'vfat'
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
  {%- for mntPt in fstabMnts.keys() %}
  {%- set mntFstype = fstabMnts[mntPt]['fstype'] %}
    {%- if mntFstype in mediaFStypes %}
      {%- set mntDev = fstabMnts[mntPt]['device'] %}
      {%- set mntDump = fstabMnts[mntPt]['dump'] %}
      {%- set mntOpts = fstabMnts[mntPt]['opts']%}
      {%- set mntPass = fstabMnts[mntPt]['pass'] %}

      {%- if wantOpt in mntOpts %}
test_{{ stig_id }}-{{ mntPt }}:
  cmd.run:
    - name: 'printf "\nchanged=no comment=''Mount-def for {{ mntPt }} already has {{ wantOpt }} mount-option: state ok.''\n"'
    - cwd: /root
    - stateful: True
      {%- else %}
        {%- do mntOpts.append(wantOpt) %}
fix_{{ stig_id }}-{{ mntPt }}:
  module.run:
    - name: 'mount.set_fstab'
    - m_name: '{{ mntPt }}'
    - device: '{{ mntDev }}'
    - fstype: '{{ mntFstype }}'
    - opts: '{{ mntOpts|join(",") }}'
    - dump: '{{ mntDump }}'
    - pass_num: '{{ mntPass }}'
      {%- endif %}
    {%- endif %}
  {%- endfor %}
{%- endif %}
