# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-51337
# Finding ID:	V-51337
# Version:	RHEL-06-000017
# Finding Level:	Medium
#
#     Disabling a major host protection feature, such as SELinux, at boot 
#     time prevents it from confining system services at boot time. Further, 
#     it increases the chances that it will remain off during system 
#     operation. 
#
#  CCI: CCI-000366
#  NIST SP 800-53 :: CM-6 b
#  NIST SP 800-53A :: CM-6.1 (iv)
#  NIST SP 800-53 Revision 4 :: CM-6 b
#
#############################################################################

script_V51337-describe:
  cmd.script:
    - source: salt://ash-linux/STIGbyID/cat2/files/V51337.sh

#########################################
# Ensure SELinux is active at kernel load
{% if salt['file.search']('/boot/grub/grub.conf', 'kernel.*selinux=0') %}

file_V51337-repl:
  file.replace:
    - name: '/boot/grub/grub.conf'
    - pattern: ' selinux=0'
    - repl: ''

{% else %}
status_V51337:
  cmd.run:
    - name: 'echo "SELinux not disabled in GRUB"'
{% endif %}
