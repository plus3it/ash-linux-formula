# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38585
# Finding ID:	V-38585
# Version:	RHEL-06-000068
# Finding Level:	Medium
#
#     The system boot loader must require authentication. Password 
#     protection on the boot loader configuration ensures users with 
#     physical access cannot trivially alter important bootloader settings. 
#     These include which kernel to use, and whether to enter ...
#
#  CCI: CCI-000213
#  NIST SP 800-53 :: AC-3
#  NIST SP 800-53A :: AC-3.1
#  NIST SP 800-53 Revision 4 :: AC-3
#
############################################################

script_V38585-describe:
  cmd.script:
  - source: salt://STIGbyID/cat2/files/V38585.sh

# Conditional replace or append
{% if not salt['file.search']('/boot/grub/grub.conf', '^password --encrypted "$6') %}
cmd_V38585-notice:
  cmd.run:
  - name: 'echo "GRUB not password-protected with SHA512 password: manual remediation required"'
{% endif %}


