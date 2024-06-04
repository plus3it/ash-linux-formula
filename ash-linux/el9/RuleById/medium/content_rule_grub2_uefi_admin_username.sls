# Rule ID:              content_rule_grub2_uefi_admin_username
# Finding Level:        high
#
# Rule Summary:
#       To maximize the protection of the GRUB2 boot-loader, select a unique
#       name for the password-protected superuser account. Modify the
#       /etc/grub.d/01_users configuration file to reflect the changed account
#       name
#
# Identifiers:
#   - content_rule_grub2_uefi_admin_username
#
# References:
#   - ANSSI
#     - BP28(R17)
#   - CIS-CSC
#     - 11
#     - 12
#     - 14
#     - 15
#     - 16
#     - 18
#     - 3
#     - 5
#   - COBIT5
#     - DSS05.02
#     - DSS05.04
#     - DSS05.05
#     - DSS05.07
#     - DSS06.03
#     - DSS06.06
#   - CUI
#     - 3.4.5
#   - DISA
#     - CCI-000213
#   - HIPAA
#     - 164.308(a)(1)(ii)(B)
#     - 164.308(a)(7)(i)
#     - 164.308(a)(7)(ii)(A)
#     - 164.310(a)(1)
#     - 164.310(a)(2)(i)
#     - 164.310(a)(2)(ii)
#     - 164.310(a)(2)(iii)
#     - 164.310(b)
#     - 164.310(c)
#     - 164.310(d)(1)
#     - 164.310(d)(2)(iii)
#   - ISA-62443-2009
#     - 4.3.3.2.2
#     - 4.3.3.5.1
#     - 4.3.3.5.2
#     - 4.3.3.5.3
#     - 4.3.3.5.4
#     - 4.3.3.5.5
#     - 4.3.3.5.6
#     - 4.3.3.5.7
#     - 4.3.3.5.8
#     - 4.3.3.6.1
#     - 4.3.3.6.2
#     - 4.3.3.6.3
#     - 4.3.3.6.4
#     - 4.3.3.6.5
#     - 4.3.3.6.6
#     - 4.3.3.6.7
#     - 4.3.3.6.8
#     - 4.3.3.6.9
#     - 4.3.3.7.1
#     - 4.3.3.7.2
#     - 4.3.3.7.3
#     - 4.3.3.7.4
#   - ISA-62443-2013
#     - SR 1.1
#     - SR 1.10
#     - SR 1.11
#     - SR 1.12
#     - SR 1.13
#     - SR 1.2
#     - SR 1.3
#     - SR 1.4
#     - SR 1.5
#     - SR 1.6
#     - SR 1.7
#     - SR 1.8
#     - SR 1.9
#     - SR 2.1
#     - SR 2.2
#     - SR 2.3
#     - SR 2.4
#     - SR 2.5
#     - SR 2.6
#     - SR 2.7
#   - ISO27001-2013
#     - A.6.1.2
#     - A.7.1.1
#     - A.9.1.2
#     - A.9.2.1
#     - A.9.2.3
#     - A.9.4.1
#     - A.9.4.4
#     - A.9.4.5
#   - NIST
#     - CM-6(a)
#   - NIST-CSF
#     - PR.AC-4
#     - PR.AC-6
#     - PR.PT-3
#   - OSPP
#     - FIA_UAU.1
#   - OS-SRG
#     - SRG-OS-000080-GPOS-00048
#
################################################################################
{%- set stig_id = 'grub2_uefi_admin_username' %}
{%- set helperLoc = tpldir ~ '/files' %}
{#- Get the `tplroot` from `tpldir` #}
{%- set tplroot = tpldir.split('/')[0] %}
{%- from tplroot ~ '/el9/RuleById/common/grub2_info.jinja' import grubEncryptedPass with context %}
{%- from tplroot ~ '/el9/RuleById/common/grub2_info.jinja' import grubUser with context %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}
{%- set mustSet = salt.pillar.get('ash-linux:lookup:grub-passwd', '') %}
{%- set grubCfg = '/boot/grub2/grub.cfg' %}
{%- set grubUserFile = '/etc/grub.d/01_users' %}
{%- set grubPassFile = '/boot/grub2/user.cfg' %}
{%- set grubUtil = '/bin/grub2-mkpasswd-pbkdf2' %}

{{ stig_id }}-description:
  test.show_notification:
    - text: |
        --------------------------------------------
        STIG Finding ID: {{ stig_id }}
           The grub2 boot-loader should have a
           customized superuser account name
        ---------------------------------------------

{%- if stig_id in skipIt %}
notify_{{ stig_id }}-skipSet:
  test.show_notification:
    - text: |
        Handler for {{ stig_id }} has been selected for skip.
{%- elif salt.file.directory_exists('/sys/firmware/efi') %}
Set GRUB2 super-user to {{ grubUser }} in {{ grubUserFile }}:
  file.replace:
    - name: '{{ grubUserFile }}'
    - pattern: '^(|\s*)(set superusers=)\".*\"'
    - repl: '\1\2="{{ grubUser }}"'

Update {{ grubCfg }} as needed:
  cmd.run:
    - name: '/usr/sbin/grub2-mkconfig -o {{ grubCfg }}'
    - onchanges:
      - file: Set GRUB2 super-user to {{ grubUser }} in {{ grubUserFile }}
{%- else %}
Why Skip ({{ stig_id }}) - No EFI Support:
notify_{{ stig_id }}-skipSet:
  test.show_notification:
    - text: |
        ---------------------------------------
        This system does not support UEFI-boot
        ---------------------------------------
{%- endif %}
