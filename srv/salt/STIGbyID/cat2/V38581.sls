# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38581
# Finding ID:	V-38581
# Version:	RHEL-06-000066
# Finding Level:	Medium
#
#     The system boot loader configuration file(s) must be group-owned by 
#     root. The "root" group is a highly-privileged group. Furthermore, the 
#     group-owner of this file should not have any access privileges anyway.
#
############################################################

script_V38581-describe:
  cmd.script:
  - source: salt://STIGbyID/cat2/files/V38581.sh

{% if salt['file.file_exists']('/boot/grub/grub.conf') %}
file_V38581-bootGrubGrub:
  file.managed:
  - name: '/boot/grub/grub.conf'
  - group: root

file_V38581-etcGrub:
  file.symlink:
  - name: '/etc/grub.conf'
  - target: '/boot/grub/grub.conf'
{% elif salt['file.file_exists']('/boot/grub.conf') %}
file_V38581-hardlink:
  module.run:
  - name: 'file.link'
  - src: '/boot/grub.conf'
  - path: '/boot/grub/grub.conf'

file_V38581-etcGrub:
  file.symlink:
  - name: '/etc/grub.conf'
  - target: '/boot/grub/grub.conf'
{% endif %}

{% if not salt['file.file_exists']('/boot/grub.conf') %}
file_V38581-hardlink:
  module.run:
  - name: 'file.link'
  - src: '/boot/grub/grub.conf'
  - path: '/boot/grub.conf'
{% endif %}
