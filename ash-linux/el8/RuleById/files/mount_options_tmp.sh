#!/bin/sh
#
# Finding ID:	
# Version: mount_option_tmp_noexec
# SRG ID:	
# Finding Level:	medium
#
# Rule Summary:
#       The noexec mount option can be used to prevent binaries
#       from being executed out of /tmp.
#
# Identifiers:
#   - CCE-82139-7
#
# References:
#   - BP28(R12)
#   - 11
#   - 13
#   - 14
#   - 3
#   - 8
#   - 9
#   - APO13.01
#   - BAI10.01
#   - BAI10.02
#   - BAI10.03
#   - BAI10.05
#   - DSS05.02
#   - DSS05.05
#   - DSS05.06
#   - DSS06.06
#   - CCI-001764
#   - 4.3.3.5.1
#   - 4.3.3.5.2
#   - 4.3.3.5.3
#   - 4.3.3.5.4
#   - 4.3.3.5.5
#   - 4.3.3.5.6
#   - 4.3.3.5.7
#   - 4.3.3.5.8
#   - 4.3.3.6.1
#   - 4.3.3.6.2
#   - 4.3.3.6.3
#   - 4.3.3.6.4
#   - 4.3.3.6.5
#   - 4.3.3.6.6
#   - 4.3.3.6.7
#   - 4.3.3.6.8
#   - 4.3.3.6.9
#   - 4.3.3.7.1
#   - 4.3.3.7.2
#   - 4.3.3.7.3
#   - 4.3.3.7.4
#   - 4.3.4.3.2
#   - 4.3.4.3.3
#   - SR 1.1
#   - SR 1.10
#   - SR 1.11
#   - SR 1.12
#   - SR 1.13
#   - SR 1.2
#   - SR 1.3
#   - SR 1.4
#   - SR 1.5
#   - SR 1.6
#   - SR 1.7
#   - SR 1.8
#   - SR 1.9
#   - SR 2.1
#   - SR 2.2
#   - SR 2.3
#   - SR 2.4
#   - SR 2.5
#   - SR 2.6
#   - SR 2.7
#   - SR 7.6
#   - A.11.2.9
#   - A.12.1.2
#   - A.12.5.1
#   - A.12.6.2
#   - A.14.2.2
#   - A.14.2.3
#   - A.14.2.4
#   - A.8.2.1
#   - A.8.2.2
#   - A.8.2.3
#   - A.8.3.1
#   - A.8.3.3
#   - A.9.1.2
#   - CIP-003-8 R5.1.1
#   - CIP-003-8 R5.3
#   - CIP-004-6 R2.3
#   - CIP-007-3 R2.1
#   - CIP-007-3 R2.2
#   - CIP-007-3 R2.3
#   - CIP-007-3 R5.1
#   - CIP-007-3 R5.1.1
#   - CIP-007-3 R5.1.2
#   - CM-7(a)
#   - CM-7(b)
#   - CM-6(a)
#   - AC-6
#   - AC-6(1)
#   - MP-7
#   - PR.IP-1
#   - PR.PT-2
#   - PR.PT-3
#   - SRG-OS-000368-GPOS-00154
#   - RHEL-08-040125
#   - 1.1.2.3
#   - SV-230513r627750_rule
#
#################################################################
{%- set stig_id = 'mount_options_tmp' %}
{%- set helperLoc = 'ash-linux/el8/RuleById/files' %}
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
#
#################################################################
# Standard outputter function
diag_out() {
   echo "${1}"
}

diag_out "--------------------------------------"
diag_out "STIG Finding ID: mount_options_tmp"
diag_out "   Set nodev, noexec and nosuid mount-"
diag_out "   options on /tmp to prevent abuses."
diag_out "--------------------------------------"
