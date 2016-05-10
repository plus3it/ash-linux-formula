# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38671
# Finding ID:	V-38671
# Version:	RHEL-06-000288
# Finding Level:	Medium
#
#     The sendmail package must be removed. The sendmail software was not 
#     developed with security in mind and its design prevents it from being 
#     effectively contained by SELinux. Postfix should be used instead.
#
#  CCI: CCI-000366
#  NIST SP 800-53 :: CM-6 b
#  NIST SP 800-53A :: CM-6.1 (iv)
#  NIST SP 800-53 Revision 4 :: CM-6 b
#
############################################################

{%- set stigId = 'V38671' %}
{%- set helperLoc = 'ash-linux/el6/STIGbyID/cat2/files' %}

script_{{ stigId }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stigId }}.sh
    - cwd: '/root'

pkg_{{ stigId }}-remove:
  pkg.purged:
    - name: 'sendmail'
