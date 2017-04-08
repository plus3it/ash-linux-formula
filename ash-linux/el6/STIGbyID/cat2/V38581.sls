# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38581
# Finding ID:	V-38581
# Version:	RHEL-06-000066
# Finding Level:	Medium
#
#     The system boot loader configuration file(s) must be group-owned by
#     root. The "root" group is a highly-privileged group. Furthermore, the
#     group-owner of this file should not have any access privileges anyway.
#
#  CCI: CCI-000366
#  NIST SP 800-53 :: CM-6 b
#  NIST SP 800-53A :: CM-6.1 (iv)
#  NIST SP 800-53 Revision 4 :: CM-6 b
#
############################################################

{%- set stig_id = 'V38581' %}
{%- set helperLoc = 'ash-linux/el6/STIGbyID/cat2/files' %}
{%- set grubFiles = ['grub.conf', 'menu.lst'] %}

script_{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stig_id }}.sh
    - cwd: '/root'

file_{{ stig_id }}-bootGrubGrub:
  file.managed:
    - name: '/boot/grub/grub.conf'
    - replace: False
    - group: root

file_{{ stig_id }}-etcGrub:
  file.symlink:
    - name: '/etc/grub.conf'
    - target: '/boot/grub/grub.conf'

file_{{ stig_id }}-menuLst:
  file.symlink:
    - name: '/boot/grub/menu.lst'
    - target: './grub.conf'


# Any grub.conf or menu.lst that exists in "/boot" are superfluous
{%- for chkFile in grubFiles %}
{%- if salt.file.file_exists('/boot/' + chkFile) %}
notify_{{ stig_id }}-{{ chkFile }}:
  cmd.run:
    - name: 'printf "
*********************************************\n
* NOTE: /boot/{{ chkFile }} is superfluous. Remove\n
*       file to prevent unexpected behaviors.\n
*********************************************\n
"'
{%- endif %}
{%- endfor %}
