# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38443
# Finding ID:	V-38443
# Version:	RHEL-06-000036
# Finding Level:	Medium
#
#     The /etc/gshadow file must be owned by root. The "/etc/gshadow" file 
#     contains group password hashes. Protection of this file is critical 
#     for system security.
#
#  CCI: CCI-000366
#  NIST SP 800-53 :: CM-6 b
#  NIST SP 800-53A :: CM-6.1 (iv)
#  NIST SP 800-53 Revision 4 :: CM-6 b
#
############################################################

script_V38443-describe:
  cmd.script:
    - source: salt://STIGbyID/cat2/files/V38443.sh

{% if salt['file.get_user']('/etc/gshadow') == 'root' %}
notify_V38443-ownership:
  cmd.run:
    - name: 'echo "Info: ''/etc/gshadow'' file already owned by ''root''."'
{% else %}
notify_V38443-ownership:
  cmd.run:
    - name: 'echo "WARNING: ''/etc/gshadow'' not owned by ''root''. Fixing..." ; exit 1'

file_V38443:
  file.managed:
    - name: /etc/gshadow
    - user: root
    - group: root
    - mode: '0000'
{% endif %}
