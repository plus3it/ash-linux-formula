# STIG ID:	RHEL-07-010491
# Rule ID:	SV-95719r1_rule
# Vuln ID:	V-81007
# SRG ID:	SRG-OS-000080-GPOS-00048
# Finding Level:	high
#
# Rule Summary:
#	Systems using Unified Extensible Firmware Interface (UEFI)
#	must require authentication upon booting into single-user and
#	maintenance modes.
#
# CCI-000213
#    NIST SP 800-53 :: AC-3
#    NIST SP 800-53A :: AC-3.1
#    NIST SP 800-53 Revision 4 :: AC-3
#
#################################################################
{%- set stig_id = 'RHEL-07-010491' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat1/files' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}
{%- if salt.grains.get('os') == 'CentOS' %}
  {%- set mainCfg = '/boot/efi/EFI/centos/grub.cfg' %}
{%- elif salt.grains.get('os') == 'RedHat' %}
  {%- set mainCfg = '/boot/efi/EFI/redhat/grub.cfg' %}
{%- endif %}

{%- set srcCfg = '/etc/grub.d/10_linux' %}
{%- set dummyPass = '4BadPassw0rd' %}
{%- set grubPass = salt['cmd.shell']('printf "' + dummyPass +
                       '\n' + dummyPass + '\n" | grub2-mkpasswd-pbkdf2 ' +
                       '2>&1 | grep "password is" ' +
                       '| sed "s/^.*password is //"') %}

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
  {%- if salt.file.directory_exists('/sys/firmware/efi') %}
    {%- if salt.file.search(mainCfg, 'password_pbkdf2') %}
script_{{ stig_id }}-{{ mainCfg }}:
  cmd.run:
    - name: 'printf "\nchanged=no comment=''Password - or pointer - already set in {{ mainCfg }}.''\n"'
    - cwd: /root
    - stateful: True
      {%- if salt.file.search(srcCfg, 'superusers="root" password_pbkdf2') %}
script_{{ stig_id }}-{{ srcCfg }}:
  cmd.run:
    - name: 'printf "\nchanged=no comment=''Password already set in {{ srcCfg }}.''\n"'
    - cwd: /root
    - stateful: True
      {%- else %}
file_{{ stig_id }}-{{ srcCfg }}:
  file.append:
    - name: '{{ srcCfg }}'
    - text: |-
        # Added per STIG-ID {{ stig_id }}
        set superusers="root" password_pbkdf2 root {{ grubPass }}
cmd_{{ stig_id }}-{{ mainCfg }}:
  cmd.run:
    - name: 'grub2-mkconfig --output={{ mainCfg }}'
    - cwd: /root
    - watch:
      - file: file_{{ stig_id }}-{{ srcCfg }}
      {%- endif %}
    {%- else %}
file_{{ stig_id }}-{{ srcCfg }}:
  file.append:
    - name: '{{ srcCfg }}'
    - text: |-
        # Added per STIG-ID {{ stig_id }}
        set superusers="root" password_pbkdf2 root {{ grubPass }}
cmd_{{ stig_id }}-{{ mainCfg }}:
  cmd.run:
    - name: 'grub2-mkconfig --output={{ mainCfg }}'
    - cwd: /root
    - watch:
      - file: file_{{ stig_id }}-{{ srcCfg }}
    {%- endif %}
  {%- else %}
cmd_{{ stig_id }}-notice:
  cmd.run:
    - name: 'printf "\nchanged=no comment=''System not booted from EFI.''\n"'
    - cwd: /root
    - stateful: True
  {%- endif %}
{%- endif %}
