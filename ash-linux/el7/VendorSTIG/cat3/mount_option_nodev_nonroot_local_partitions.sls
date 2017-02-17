# Finding ID:	
# Version:	mount_option_nodev_nonroot_local_partitions
# SRG ID:	
# Finding Level:	low
#
# Rule Summary:
#	The nodev mount option prevents files from being
#	interpreted as character or block devices. The only
#	legitimate location for device files is the /dev
#	directory located on the root partition. The only
#	exception to this is chroot jails, for which it is not
#	advised to set nodev on these filesystems.
#
# CCI-xxxxxx CCI-xxxxxx
#    NIST SP 800-53 Revision 4 :: CM-7
#    NIST SP 800-53 Revision 4 :: MP-2
#    CIS RHEL 7 Benchmark 1.1.0 :: 1.1.11
#
#################################################################
{%- set stig_id = 'mount_option_nodev_nonroot_local_partitions' %}
{%- set helperLoc = 'ash-linux/el7/VendorSTIG/cat3/files' %}
{%- set fstabMnts = salt.mount.fstab() %}
{%- set skipMnts = [
                    '/',
                    '/dev/shm',
                    'swap'
                      ] %}
{%- set mntList = fstabMnts.keys() %}
{%- set mntOpt = 'nodev' %}

script_{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stig_id }}.sh
    - cwd: /root

{%- for targMnt in mntList %}
  {% if targMnt not in skipMnts %}
  {%- set mntDev = fstabMnts[targMnt]['device'] %}
  {%- set mntDump = fstabMnts[targMnt]['dump'] %}
  {%- set mntOpts = fstabMnts[targMnt]['opts'] %}
  {%- set mntPass = fstabMnts[targMnt]['pass'] %}
  {%- set mntFstype = fstabMnts[targMnt]['fstype'] %}

file_{{ stig_id }}-{{ targMnt }}:
  module.run:
    - name: 'mount.set_fstab'
    - m_name: '{{ targMnt }}'
    - device: '{{ mntDev }}'
    - fstype: '{{ mntFstype }}'
    - opts: '{{ mntOpts|join(",") }},{{ mntOpt }}'
    - dump: '{{ mntDump }}'
    - pass_num: '{{ mntPass }}'

  {%- endif %}
{%- endfor %}
