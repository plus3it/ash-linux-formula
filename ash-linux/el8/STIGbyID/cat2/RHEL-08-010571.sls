# Ref Doc:    STIG - RHEL 8 v1r7
# Finding ID: V-230300
# Rule ID:    SV-230300r743959_rule
# STIG ID:    RHEL-08-010571
# SRG ID:     SRG-OS-000480-GPOS-00227
#
# Finding Level: medium
#
# Rule Summary:
#       The OS must prevent files with the setuid and setgid bit set from
#       being executed on the /boot directory
#
# References:
#   CCI:
#     - CCI-000366
#
# NIST SP 800-53 :: CM-6 b
# NIST SP 800-53A :: CM-6.1 (iv)
# NIST SP 800-53 Revision 4 :: CM-6 b
#
###########################################################################
{%- set stig_id = 'RHEL-08-010571' %}
{%- set helperLoc = tpldir ~ '/files' %}
{%- set optionsFile ='/etc/systemd/system/boot.mount.d/options.conf' %}
{%- set mntOpt = [
  'nosuid',
] %}
{%- set targMnt = '/boot' %}

script_{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stig_id }}.sh
    - cwd: /root

# /boot owned by systemd...
file_{{ stig_id }}-{{ targMnt }}:
  file.managed:
    - name: '{{ optionsFile }}'
    - user: 'root'
    - group: 'root'
    - mode: '0644'
    - makedirs: True
    - dir_mode: '0755'
    - contents: |-
        [Mount]
        Options=strictatime,{{ mntOpt|join(",") }}
        DirectoryMode=0700
