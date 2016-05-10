# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-51379
# Rule ID:		selinux_all_devicefiles_labeled
# Finding ID:		V-51379
# Version:		RHEL-06-000025
# SCAP Security ID:	CCE-26774-0
# Finding Level:	Low
#
#     All device files must be monitored by the system Linux Security 
#     Module. If a device file carries the SELinux type "unlabeled_t", then 
#     SELinux cannot properly restrict access to the device file.
#
#  CCI: CCI-000366
#  NIST SP 800-53 :: CM-6 b
#  NIST SP 800-53A :: CM-6.1 (iv)
#  NIST SP 800-53 Revision 4 :: CM-6 b
#
############################################################

{%- set stigId = 'V51379' %}
{%- set helperLoc = 'ash-linux/el6/STIGbyID/cat3/files' %}

script_{{ stigId }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stigId }}.sh
    - cwd: /root

# Need to replace this with custom module...
script_{{ stigId }}-Verfiy:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stigId }}-helper.sh
    - cwd: /root
