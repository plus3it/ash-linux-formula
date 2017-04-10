# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38546
# Finding ID:	V-38546
# Version:	RHEL-06-000098
# Finding Level:	Medium
#
#     The IPv6 protocol handler must not be bound to the network stack
#     unless needed. Any unnecessary network stacks - including IPv6 -
#     should be disabled, to reduce the vulnerability to exploitation.
#
#  CCI: CCI-000366
#  NIST SP 800-53 :: CM-6 b
#  NIST SP 800-53A :: CM-6.1 (iv)
#  NIST SP 800-53 Revision 4 :: CM-6 b
#
############################################################

{%- set stig_id = '38546' %}
{%- set helperLoc = 'ash-linux/el6/STIGbyID/cat2/files' %}
{%- set file = '/etc/modprobe.d/disabled.conf' %}

file-V{{ stig_id }}-touchRules:
  file.touch:
    - name: '{{ file }}'

file_V{{ stig_id }}-appendBlacklist:
  file.append:
    - name: '{{ file }}'
    - text: 'options ipv6 disable=1'
    - require:
      - file: file-V{{ stig_id }}-touchRules
    - onlyif:
      - 'test -f {{ file }}'
