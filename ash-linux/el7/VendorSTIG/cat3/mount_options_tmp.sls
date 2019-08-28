# Finding ID:	
# Version:	mount_option_tmp_nodev
# 		mount_option_tmp_noexec
# 		mount_option_tmp_nosuid
# SRG ID:	
# Finding Level:	low
#
# Rule Summary:
#       The nodev mount option can be used to prevent device
#       files from being created in /tmp.
#
#       The noexec mount option can be used to prevent binaries
#       from being executed out of /tmp.
#
#       The nosuid mount option can be used to prevent
#       execution of setuid programs in /tmp.
#
# CCI-xxxxxx CCI-xxxxxx
#    NIST SP 800-53 Revision 4 :: CM-7
#    NIST SP 800-53 Revision 4 :: MP-2
#    CIS RHEL 7 Benchmark 1.1.0 :: 1.1.2
#    CIS RHEL 7 Benchmark 1.1.0 :: 1.1.4
#    CIS RHEL 7 Benchmark 1.1.0 :: 1.1.3
#
#################################################################
{%- set stig_id = 'mount_options_tmp' %}
{%- set helperLoc = 'ash-linux/el7/VendorSTIG/cat3/files' %}
{%- set optionsFile ='/etc/systemd/system/tmp.mount.d/options.conf' %}
{%- set mntOpt = [
                  'nosuid',
                  'noexec',
                  'nodev'
                    ]%}
{%- set targMnt = '/tmp' %}

script_{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stig_id }}.sh
    - cwd: /root

# /tmp owned by systemd...
{%- if salt.service.available('tmp.mount') %}
file_{{ stig_id }}-{{ targMnt }}:
  file.managed:
    - name: '{{ optionsFile }}'
    - user: 'root'
    - grou: 'root'
    - mode: '0644'
    - makedirs: True
    - dir_mode: '0755'
    - contents: |-
        [Mount]
        Options=mode=1777,strictatime,{{ mntOpt|join(",") }}

# /tmp is standard filesystem...
{%- elif salt.file.search('/etc/fstab', targMnt) %}
  {%- set fstabMnts = salt.mount.fstab() %}
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
    - opts: '{{ mntOpts|join(",") }},{{ mntOpt|join(",") }}'
    - dump: '{{ mntDump }}'
    - pass_num: '{{ mntPass }}'
{%- endif %}
