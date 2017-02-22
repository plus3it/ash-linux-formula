# Finding ID:	
# Version:	mount_option_dev_shm_noexec
# SRG ID:	
# Finding Level:	low
#
# Rule Summary:
#	Allowing users to execute binaries from world-writable
#	directories such as /dev/shm can expose the system to
#	potential compromise.
#
# CCI-xxxxxx CCI-xxxxxx
#    NIST SP 800-53 Revision 4 :: CM-7
#    NIST SP 800-53 Revision 4 :: MP-2
#    CIS RHEL 7 Benchmark 1.1.0 :: 1.1.16
#
#################################################################
{%- set stig_id = 'mount_option_dev_shm_noexec' %}
{%- set helperLoc = 'ash-linux/el7/VendorSTIG/cat3/files' %}
{%- set targMnt = '/dev/shm' %}
{%- set mntOpt = 'noexec' %}

script_{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stig_id }}.sh
    - cwd: /root

{%- if salt.file.search('/etc/fstab', targMnt) %}
  {%- set fstabMnts = salt.mount.fstab() %}
  {%- set mntDev = fstabMnts[targMnt]['device'] %}
  {%- set mntDump = fstabMnts[targMnt]['dump'] %}
  {%- set mntOpts = fstabMnts[targMnt]['opts'] %}
  {%- set mntPass = fstabMnts[targMnt]['pass'] %}
  {%- set mntFstype = fstabMnts[targMnt]['fstype'] %}

  {%- if mntOpt in mntOpts %}
notify_{{ stig_id }}-{{ targMnt }}:
  cmd.run:
    - name: 'printf "\nchanged=no comment=''Mount-def for {{ targMnt }} already has {{ mntOpt }} mount-option: state ok.''\n"'
    - cwd: /root
    - stateful: True
  {%- else %}
    {% do mntOpts.append(mntOpt) %}

fix_{{ stig_id }}-{{ targMnt }}:
  module.run:
    - name: 'mount.set_fstab'
    - m_name: '{{ targMnt }}'
    - device: '{{ mntDev }}'
    - fstype: '{{ mntFstype }}'
    - opts: '{{ mntOpts|join(",") }}'
    - dump: '{{ mntDump }}'
    - pass_num: '{{ mntPass }}'

  {%- endif %}
{%- else %}
  {%- set fstabMnts = salt.mount.active() %}
  {%- set mntDev = fstabMnts[targMnt]['device'] %}
  {%- set mntOpts = fstabMnts[targMnt]['opts'] %}
  {%- set mntFstype = fstabMnts[targMnt]['fstype'] %}

  {%- if not mntOpt in mntOpts %}
    {% do mntOpts.append(mntOpt) %} 
  {%- endif %}

fix_{{ stig_id }}-{{ targMnt }}:
  module.run:
    - name: 'mount.set_fstab'
    - m_name: '{{ targMnt }}'
    - device: '{{ mntDev }}'
    - fstype: '{{ mntFstype }}'
    - opts: '{{ mntOpts|join(",") }}'
    - dump: '0'
    - pass_num: '0'

{%- endif %}
