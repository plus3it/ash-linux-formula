# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38664
# Finding ID:	V-38664
# Version:	RHEL-06-000279
# Finding Level:	Medium
#
#     The system package management tool must verify ownership on all files 
#     and directories associated with the audit package. Ownership of audit 
#     binaries and configuration files that is incorrect could allow an 
#     unauthorized user to gain privileges that they should not have. The 
#     ownership set by the vendor should be ...
#
#  CCI: CCI-001494
#  NIST SP 800-53 :: AU-9
#  NIST SP 800-53A :: AU-9.1
#  NIST SP 800-53 Revision 4 :: AU-9
#
############################################################
{%- set stigId = 'V38664' %}
{%- set helperLoc = 'ash-linux/el6/STIGbyID/cat2/files' %}

script_{{ stigId }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stigId }}.sh
    - cwd: '/root'

# NEED TO INVESTIGATE USE OF pkg.verify MODULE

script_{{ stigId }}-helper:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stigId }}-helper.sh
    - cwd: '/root'

