# Finding ID:	RHEL-07-010460
# Version:	RHEL-07-010460_rule
# SRG ID:	SRG-OS-000080-GPOS-00048
# Finding Level:	high
#
# Rule Summary:
#	Systems with a Basic Input/Output System (BIOS) must
#	require authentication upon booting into single-user and
#	maintenance modes.
#
# CCI-000213
#    NIST SP 800-53 :: AC-3
#    NIST SP 800-53A :: AC-3.1
#    NIST SP 800-53 Revision 4 :: AC-3
#
#################################################################
{%- set stig_id = 'RHEL-07-010460' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat1/files' %}
{%- set mainCfg = '/boot/grub2/grub.cfg' %}
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

{%- if salt.file.search(mainCfg, 'password_pbkdf2', ignore_if_missing=True) %}
script_{{ stig_id }}-{{ mainCfg }}:
  cmd.run:
    - name: 'printf "\nchanged=no comment=''Password - or pointer - already set in {{ mainCfg }}.''\n"'
    - cwd: /root
  {%- if salt.file.search(srcCfg, 'superusers="root" password_pbkdf2') %}
script_{{ stig_id }}-{{ srcCfg }}:
  cmd.run:
    - name: 'printf "\nchanged=no comment=''Password already set in {{ srcCfg }}.''\n"'
    - cwd: /root
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
{%- elif salt.file.file_exists(srcCfg) %}
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
