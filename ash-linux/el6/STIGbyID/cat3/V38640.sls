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

{%- set stigId = 'V38640' %}
{%- set helperLoc = 'ash-linux/el6/STIGbyID/cat3/files' %}

script_{{ stigId }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stigId }}.sh
    - cwd: /root

{%- if salt.pkg.version('abrt') %}
svc_{{ stigId }}-abrtdEnabled:
  service.disabled:
    - name: 'abrtd'

svc_{{ stigId }}-abrtdRunning:
  service.dead:
    - name: 'abrtd'
{%- else %}
notice_{{ stigId }}-notPresent:
  cmd.run:
    - name: 'echo "The ABRT subsystem is not installed"'
{%- endif %}
