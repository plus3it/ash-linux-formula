# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38544
# Finding ID:	V-38544
# Version:	RHEL-06-000097
# Finding Level:	Medium
#
#     The system must use a reverse-path filter for IPv4 network traffic 
#     when possible by default. Enabling reverse path filtering drops 
#     packets with source addresses that should not have been able to be 
#     received on the interface they were received on. It should not be 
#     used on systems which are ...
#
############################################################

script_V38544-describe:
  cmd.script:
  - source: salt://STIGbyID/cat2/files/V38544.sh

{% if salt['file.search']('/etc/sysctl.conf', 'sysctl net.ipv4.conf.default.rp_filter') %}
file_V38544-repl:
  file.replace:
  - name: '/etc/sysctl.conf'
  - pattern: '^sysctl net.ipv4.conf.default.rp_filter.*$'
  - repl: 'net.ipv4.conf.default.rp_filter = 1'
{% else %}
file_V38544-append:
  file.append:
  - name: '/etc/sysctl.conf'
  - text:
    - ' '
    - '# Enable TCP SYN-cookies'
    - 'sysctl net.ipv4.conf.default.rp_filter = 1'
{% endif %}
