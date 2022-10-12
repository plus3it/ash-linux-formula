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
