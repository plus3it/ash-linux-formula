# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38537
# Rule ID:		sysctl_net_ipv4_icmp_ignore_bogus_error_responses
# Finding ID:		V-38537
# Version:		RHEL-06-000093
# SCAP Security ID:	CCE-26993-6
# Finding Level:	Low
#
#     The system must ignore ICMPv4 bogus error responses. Ignoring bogus 
#     ICMP error responses reduces log size, although some activity would 
#     not be logged.
#
############################################################

script_V38537-describe:
  cmd.script:
    - source: salt://ash-linux/STIGbyID/cat3/files/V38537.sh

{% if salt['sysctl.get']('net.ipv4.icmp_ignore_bogus_error_responses') == '1' %}
sysctl_V38537-noRedirects:
  cmd.run:
    - name: 'echo "System already ignores bogus ICMPv4 error responses"'
{% else %}
sysctl_V38537-noRedirects:
  sysctl.present:
    - name: 'net.ipv4.icmp_ignore_bogus_error_responses'
    - value: '1'
{% endif %}
