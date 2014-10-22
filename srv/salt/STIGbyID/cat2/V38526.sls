# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38526
# Finding ID:	V-38526
# Version:	RHEL-06-000086
# Finding Level:	Medium
#
#     The system must not accept ICMPv4 secure redirect packets on any 
#     interface. Accepting "secure" ICMP redirects (from those gateways 
#     listed as default gateways) has few legitimate uses. It should be 
#     disabled unless it is absolutely required.
#
############################################################

script_V38526-describe:
  cmd.script:
  - source: salt://STIGbyID/cat2/files/V38526.sh

{% if salt['file.search']('/etc/sysctl.conf', 'net.ipv4.conf.all.secure_redirects') %}
file_V38526-repl:
  file.replace:
  - name: '/etc/sysctl.conf'
  - pattern: '^net.ipv4.conf.all.secure_redirects.*$'
  - repl: 'net.ipv4.conf.all.secure_redirects = 0'
{% else %}
file_V38526-append:
  file.append:
  - name: '/etc/sysctl.conf'
  - text:
    - ' '
    - '# Disable ICMPv4 secure redirect packtes'
    - 'net.ipv4.conf.all.secure_redirects = 0'
{% endif %}
