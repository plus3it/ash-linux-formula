# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38514
# Finding ID:	V-38514
# Version:	RHEL-06-000124
# Finding Level:	Medium
#
#     The Datagram Congestion Control Protocol (DCCP) must be disabled 
#     unless required. Disabling DCCP protects the system against 
#     exploitation of any flaws in its implementation.
#
############################################################

script_V38514-describe:
  cmd.script:
  - source: salt://STIGbyID/cat2/files/V38514.sh

{% if not salt['file.file_exists']('/etc/modprobe.d/dccp.conf') %}
file-V38514-touchRules:
  file.touch:
  - name: '/etc/modprobe.d/dccp.conf'
{% endif %}

file_V38514-appendBlacklist:
  file.append:
  - name: /etc/modprobe.d/dccp.conf
  - text: 'install dccp /bin/false'

