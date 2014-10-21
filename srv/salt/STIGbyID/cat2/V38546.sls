# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38546
# Finding ID:	V-38546
# Version:	RHEL-06-000098
# Finding Level:	Medium
#
#     The IPv6 protocol handler must not be bound to the network stack 
#     unless needed. Any unnecessary network stacks - including IPv6 - 
#     should be disabled, to reduce the vulnerability to exploitation.
#
############################################################

script_V38546-describe:
  cmd.script:
  - source: salt://STIGbyID/cat2/files/V38546.sh

{% if not salt['file.file_exists']('/etc/modprobe.d/disabled.conf') %}
file-V38546-touchRules:
  file.touch:
  - name: '/etc/modprobe.d/disabled.conf'
{% endif %}

file_V38546-appendBlacklist:
  file.append:
  - name: /etc/modprobe.d/disabled.conf
  - text: 'options ipv6 disable=1'

