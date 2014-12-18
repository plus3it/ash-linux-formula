# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38511
# Finding ID:	V-38511
# Version:	RHEL-06-000082
# Finding Level:	Medium
#
#     IP forwarding for IPv4 must not be enabled, unless the system is a 
#     router. IP forwarding permits the kernel to forward packets from one 
#     network interface to another. The ability to forward packets between 
#     two networks is only appropriate for routers.
#
#  CCI-000366
#  NIST 800-53 :: CM-6 b
#  NIST 800-53A :: CM-6.1 (iv)
#  NIST 800-53 Revision 4 :: CM-6 b
#
############################################################

script_V38511-describe:
  cmd.script:
  - source: salt://STIGbyID/cat2/files/V38511.sh

file_V38511-repl:
  file.replace:
  - name: /etc/sysctl.conf
  - pattern: '^net.ipv4.ip_forward =.*$'
  - repl: 'net.ipv4.ip_forward = 0'

