# Finding ID:
# Versions:
#   - mount_option_boot_nosuid
# SRG ID:
# Finding Level:	low
#
# Rule Summary:
#       The nosuid mount option can be used to prevent
#       execution of setuid programs in /boot.
#
# CCE-82139-7
#
#################################################################
{%- set stig_id = 'mount_options_boot' %}
{%- set helperLoc = 'ash-linux/el8/RuleById/files' %}
{%- set optionsFile ='/etc/systemd/system/boot.mount.d/options.conf' %}
{%- set mntOpt = [
                  'nosuid',
                    ]%}
{%- set targMnt = '/boot' %}

script_{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stig_id }}.sh
    - cwd: /root

# /boot owned by systemd...
{%- if salt.service.available('boot.mount') %}
file_{{ stig_id }}-{{ targMnt }}:
  file.managed:
    - name: '{{ optionsFile }}'
    - user: 'root'
    - grou: 'root'
    - mode: '0644'
    - makedirs: True
    - dir_mode: '0755'
    - selinux:
        seuser: system_u
        serole: object_r
        setype: systemd_unit_file_t
        seranage: s0
    - contents: |-
        [Mount]
        Options=mode=1777,strictatime,{{ mntOpt|join(",") }}

# /boot is standard filesystem...
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
