# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38515
# Finding ID:	V-38515
# Version:	RHEL-06-000125
# Finding Level:	Medium
#
#     The Stream Control Transmission Protocol (SCTP) must be disabled 
#     unless required. Disabling SCTP protects the system against 
#     exploitation of any flaws in its implementation.
#
#  CCI: CCI-000382
#  NIST SP 800-53 :: CM-7
#  NIST SP 800-53A :: CM-7.1 (iii)
#  NIST SP 800-53 Revision 4 :: CM-7 b
#
############################################################

script_V38515-describe:
  cmd.script:
  - source: salt://STIGbyID/cat2/files/V38515.sh

{% if not salt['file.file_exists']('/etc/modprobe.d/sctp.conf') %}
file-V38515-touchRules:
  file.touch:
  - name: '/etc/modprobe.d/sctp.conf'
{% endif %}

file_V38515-appendBlacklist:
  file.append:
  - name: /etc/modprobe.d/sctp.conf
  - text: 'install sctp /bin/false'

