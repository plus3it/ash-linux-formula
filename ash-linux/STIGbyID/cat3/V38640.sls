# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38640
# Finding ID:	V-38640
# Version:	RHEL-06-000261
# Finding Level:	Low
#
#     The Automatic Bug Reporting Tool (abrtd) service must not be running. 
#     Mishandling crash data could expose sensitive information about 
#     vulnerabilities in software executing on the local machine, as well 
#     as sensitive information from within a process's address space or
#     registers.
#
############################################################

script_V38640-describe:
  cmd.script:
  - source: salt://STIGbyID/cat3/files/V38640.sh

{% if salt['pkg.version']('abrt') %}
svc_V38640-abrtdEnabled:
  service.disabled:
  - name: 'abrtd'

svc_V38640-abrtdRunning:
 service.dead:
  - name: 'abrtd'
{% else %}
notice_V38640-notPresent:
   cmd.run:
   - name: 'echo "The ABRT subsystem is not installed"'
{% endif %}

