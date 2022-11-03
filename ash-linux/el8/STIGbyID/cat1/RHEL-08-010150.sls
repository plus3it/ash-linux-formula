# Ref Doc:    STIG - RHEL 9 v1r7
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
{%- set helperLoc = 'ash-linux/el8/STIGbyID/cat1/files' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}
{%- set mustSet = salt.pillar.get('ash-linux:lookup:grub-passwd', '') %}
{%- set grubUser = salt.pillar.get('ash-linux:lookup:grub-user', 'grubuser') %}
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
  {%- if ( not mustSet == '' ) or ( not salt.file.file_exists(grubPassFile) ) %}
user_cfg_permissions-{{ stig_id }}:
  file.managed:
    - name: '{{ grubPassFile }}'
    - user: 'root'
    - owner: 'root'
    - mode: '000600'
    - replace: false

user_cfg_selLabels-{{ stig_id }}:
  cmd.run:
    - name: 'chcon -u system_u -r object_r -t boot_t {{ grubPassFile }}'
    - cwd: /root
    - require:
      - file: user_cfg_permissions-{{ stig_id }}

user_cfg_content-{{ stig_id }}:
  cmd.run:
    - name: 'printf "GRUB2_PASSWORD=%s\n" "$( printf "{{ grubPass }}\n{{ grubPass }}\n" | {{ grubUtil }} | awk ''/grub.pbkdf/{print $NF}'' )" > {{ grubPassFile }}'
    - cwd: /root
    - require:
      - file: user_cfg_permissions-{{ stig_id }}

grubuser_superDef-{{ grubUserFile }}:
  file.replace:
    - name: {{ grubUserFile }}
    - pattern: 'superusers=".*"'
    - repl: 'superusers="{{ grubUser }}"'

grubuser_userSub-{{ grubUserFile }}:
  file.replace:
    - name: {{ grubUserFile }}
    - pattern: 'password_pbkdf2 .* \\'
    - repl: 'password_pbkdf2 {{ grubUser }} \\'

regen_grubCfg:
  cmd.run:
    - name: '/sbin/grub2-mkconfig -o /boot/grub2/grub.cfg '
    - cwd: /root
    - require:
      - file: grubuser_superDef-{{ grubUserFile }}
      - file: grubuser_userSub-{{ grubUserFile }}

  {%- else %}

notify_{{ stig_id }}-noAction:
  cmd.run:
    - name: 'printf "\nchanged=no comment=''Handler for {{ stig_id }} skipped due to pre-existence of {{ grubPassFile }}.''\n"'
    - stateful: True
    - cwd: /root
  {%- endif %}
{%- endif %}
