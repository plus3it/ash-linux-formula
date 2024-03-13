# Ref Doc:    STIG - RHEL 8 v1r7
# Finding ID: V-230235
# STIG ID:    RHEL-08-010150
# Rule ID:    SV-230235r743925_rule
# SRG ID(s):  SRG-OS-000080-GPOS-00048
# Finding Level:        high
#
# Rule Summary:
#       RHEL 8 operating systems booted with a BIOS must
#       require authentication upon booting into
#       single-user and maintenance modes
#
# References:
#   CCI:
#     - CCI-000213
#   NIST SP 800-53 :: AC-3
#   NIST SP 800-53A :: AC-3.1
#   NIST SP 800-53 Revision 4 :: AC-3
#
#################################################################
{%- set stig_id = 'RHEL-08-010150' %}
{%- set helperLoc = tpldir ~ '/files' %}
{%- from tpldir ~ '/grub2_info.jinja' import grubEncryptedPass with context %}
{%- from tpldir ~ '/grub2_info.jinja' import grubUser with context %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}
{%- set mustSet = salt.pillar.get('ash-linux:lookup:grub-passwd', '') %}
{%- set grubPass = salt.pillar.get('ash-linux:lookup:grub-passwd', 'AR34llyB4dP4ssw*rd') %}
{%- set grubUserFile = '/etc/grub.d/01_users' %}
{%- set grubPassFile = '/boot/grub2/user.cfg' %}
{%- set grubUtil = '/bin/grub2-mkpasswd-pbkdf2' %}

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
user_cfg_permissions-{{ stig_id }}:
  file.managed:
    - name: '{{ grubPassFile }}'
    - user: 'root'
    - owner: 'root'
    - mode: '000600'
    - onlyif:
      - [[ ! -d /sys/firmware/efi/ ]]
    - replace: false
    - selinux:
        serange: 's0'
        serole: 'object_r'
        setype: 'boot_t'
        seuser: 'system_u'

user_cfg_content-{{ stig_id }}:
  cmd.run:
    - name: 'printf "GRUB2_PASSWORD={{ grubEncryptedPass }})" > {{ grubPassFile }}'
    - cwd: /root
    - onchanges_in:
      - regen_grubCfg-{{ stig_id }}
    - require:
      - file: user_cfg_permissions-{{ stig_id }}

grubuser_superDef-{{ grubUserFile }}-{{ stig_id }}:
  file.replace:
    - name: '{{ grubUserFile }}'
    - pattern: 'superusers=".*"'
    - repl: 'superusers="{{ grubUser }}"'

grubuser_userSub-{{ grubUserFile }}-{{ stig_id }}:
  file.replace:
    - name: '{{ grubUserFile }}'
    - pattern: 'password_pbkdf2 .* \\'
    - repl: 'password_pbkdf2 {{ grubUser }} \\'

regen_grubCfg-{{ stig_id }}:
  cmd.run:
    - name: '/sbin/grub2-mkconfig -o /boot/grub2/grub.cfg '
    - cwd: /root
    - onchanges:
      - file: grubuser_superDef-{{ grubUserFile }}-{{ stig_id }}
      - file: grubuser_userSub-{{ grubUserFile }}-{{ stig_id }}
{%- endif %}
