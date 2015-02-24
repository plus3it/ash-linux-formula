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

{%- set stig_id = '38581' %}

script_V{{ stig_id }}-describe:
  cmd.script:
    - source: salt://ash-linux/STIGbyID/cat2/files/V{{ stig_id }}.sh

{%- if salt['file.file_exists']('/boot/grub/grub.conf') %}

file_V{{ stig_id }}-bootGrubGrub:
  file.managed:
    - name: '/boot/grub/grub.conf'
    - group: root

file_V{{ stig_id }}-etcGrub:
  file.symlink:
    - name: '/etc/grub.conf'
    - target: '/boot/grub/grub.conf'

{%- elif salt['file.file_exists']('/boot/grub.conf') %}

file_V{{ stig_id }}-hardlink:
  module.run:
    - name: 'file.link'
    - src: '/boot/grub.conf'
    - path: '/boot/grub/grub.conf'

file_V{{ stig_id }}-etcGrub:
  file.symlink:
    - name: '/etc/grub.conf'
    - target: '/boot/grub/grub.conf'

{%- endif %}

file_V{{ stig_id }}-hardlink:
  module.run:
    - name: 'file.link'
    - src: '/boot/grub/grub.conf'
    - path: '/boot/grub.conf'
    - unless: 'test -e /boot/grub.conf'
