# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38489
# Finding ID:	V-38489
# Version:	RHEL-06-000016
# Finding Level:	Medium
#
#     A file integrity tool must be installed. The AIDE package must be 
#     installed if it is to be available for integrity checking.
#
#  CCI: CCI-000663
#  NIST SP 800-53 :: SA-7
#  NIST SP 800-53A :: SA-7.1 (ii)
#
############################################################

{%- set stigId = 'V38489' %}
{%- set helperLoc = 'ash-linux/el6/STIGbyID/cat2/files' %}

script_{{ stigId }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stigId }}.sh
    - cwd: '/root'

pkg_{{ stigId }}:
  pkg.installed:
    - name: aide
