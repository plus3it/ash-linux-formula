# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38528
# Finding ID:	V-38528
# Version:	RHEL-06-000088
# Finding Level:	Low
#
#     The system must log Martian packets. The presence of "martian" 
#     packets (which have impossible addresses) as well as spoofed packets, 
#     source-routed packets, and redirects could be a sign of nefarious 
#     network activity. Logging these packets enables this activity to be 
#     detected. 
#
#  CCI: CCI-000366
#  NIST SP 800-53 :: CM-6 b
#  NIST SP 800-53A :: CM-6.1 (iv)
#  NIST SP 800-53 Revision 4 :: CM-6 b
#
############################################################

script_V38528-describe:
  cmd.script:
    - source: salt://STIGbyID/cat3/files/V38528.sh

{% if salt['sysctl.get']('net.ipv4.conf.all.log_martians') == '1' %}
sysctl_V38528-logMartians:
  cmd.run:
    - name: 'echo "Logging of Martian packets already enabled"'
{% else %}
sysctl_V38528-logMartians:
  sysctl.present:
    - name: 'net.ipv4.conf.all.log_martians'
    - value: '1'
{% endif %}
