# Ref Doc:    STIG - RHEL 8 v1r7
# Finding ID: V-230511
# Rule ID:    SV-230511r627750_rule
# STIG ID:    RHEL-08-040123
# SRG ID:     SRG-OS-000368-GPOS-00154
#
# Finding Level: medium
#
# Rule Summary:
#       The operating system must mount /tmp with the nodev
#       option
#
# References:
#   CCI:
#     - CCI-001764
#
# NIST SP 800-53 Revision 4 :: CM-7 (2)
#
#################################################################
{%- set stig_id = 'RHEL-08-040123' %}
{%- set helperLoc = tpldir ~ '/files' %}
{%- set optionsFile ='/etc/systemd/system/tmp.mount.d/options.conf' %}
{%- set mntOpt = [
  'nosuid',
  'noexec',
  'nodev'
] %}
{%- set targMnt = '/tmp' %}

script_{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stig_id }}.sh
    - cwd: /root

# /tmp owned by systemd...
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
        Options=mode=1777,strictatime,{{ mntOpt|join(",") }}
