# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38583
# Finding ID:	V-38583
# Version:	RHEL-06-000067
# Finding Level:	Medium
#
#     The system boot loader configuration file(s) must have mode 0600 or 
#     less permissive. Proper permissions ensure that only the root user 
#     can modify important boot parameters.
#
#  CCI: CCI-000366
#  NIST SP 800-53 :: CM-6 b
#  NIST SP 800-53A :: CM-6.1 (iv)
#  NIST SP 800-53 Revision 4 :: CM-6 b
#
############################################################

script_V38583-describe:
  cmd.script:
    - source: salt://STIGbyID/cat2/files/V38583.sh

{% if salt['file.file_exists']('/boot/grub/grub.conf') %}
file_V38583-bootGrubGrub:
  file.managed:
    - name: '/boot/grub/grub.conf'
    - mode: 0600

file_V38583-etcGrub:
  file.symlink:
    - name: '/etc/grub.conf'
    - target: '/boot/grub/grub.conf'
{% elif salt['file.file_exists']('/boot/grub.conf') %}
file_V38583-hardlink:
  module.run:
    - name: 'file.link'
    - src: '/boot/grub.conf'
    - path: '/boot/grub/grub.conf'

file_V38583-etcGrub:
  file.symlink:
    - name: '/etc/grub.conf'
    - target: '/boot/grub/grub.conf'
{% endif %}

{% if not salt['file.file_exists']('/boot/grub.conf') %}
file_V38583-hardlink:
  module.run:
    - name: 'file.link'
    - src: '/boot/grub/grub.conf'
    - path: '/boot/grub.conf'

file_V38583-bootGrub:
  file.managed:
    - name: '/boot/grub/grub.conf'
    - mode: 0600
{% endif %}
