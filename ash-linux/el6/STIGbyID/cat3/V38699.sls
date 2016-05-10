# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38699
# Finding ID:	V-38699
# Version:	RHEL-06-000337
# Finding Level:	Low
#
#     Allowing a user account to own a world-writable directory is 
#     undesirable because it allows the owner of that directory to remove 
#     or replace any files that may be placed in the directory by other 
#     users. 
#
#  CCI: CCI-000366
#  NIST SP 800-53 :: CM-6 b
#  NIST SP 800-53A :: CM-6.1 (iv)
#  NIST SP 800-53 Revision 4 :: CM-6 b
#
############################################################

{%- set stigId = 'V38699' %}
{%- set helperLoc = 'ash-linux/el6/STIGbyID/cat3/files' %}

script_{{ stigId }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stigId }}.sh
    - cwd: /root

# Probably need to replace this with custom module...
script_{{ stigId }}-Verfiy:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stigId }}-helper.sh
    - cwd: /root
