# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38539
# Finding ID:	V-38539
# Version:	RHEL-06-000095
# Finding Level:	Medium
#
#     The system must be configured to use TCP syncookies. A TCP SYN flood 
#     attack can cause a denial of service by filling a system's TCP 
#     connection table with connections in the SYN_RCVD state. Syncookies 
#     can be used to track a connection when a subsequent ...
#
############################################################

script_V38539-describe:
  cmd.script:
  - source: salt://STIGbyID/cat2/files/V38539.sh

{% if salt['file.search']('/etc/sysctl.conf', 'sysctl net.ipv4.tcp_syncookies') %}
file_V38539-repl:
  file.replace:
  - name: '/etc/sysctl.conf'
  - pattern: '^sysctl net.ipv4.tcp_syncookies.*$'
  - repl: 'net.ipv4.tcp_syncookies = 1'
{% else %}
file_V38539-append:
  file.append:
  - name: '/etc/sysctl.conf'
  - text:
    - ' '
    - '# Enable TCP SYN-cookies'
    - 'sysctl net.ipv4.tcp_syncookies = 1'
{% endif %}
