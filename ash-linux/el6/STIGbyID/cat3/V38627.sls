# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38627
# Finding ID:	V-38627
# Version:	RHEL-06-000256
# Finding Level:	Low
#
#     The openldap-servers package must not be installed unless required. 
#     Unnecessary packages should not be installed to decrease the attack 
#     surface of the system.
#
############################################################

{%- set stigId = 'V38627' %}
{%- set helperLoc = 'ash-linux/el6/STIGbyID/cat3/files' %}

script_{{ stigId }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stigId }}.sh
    - cwd: /root

{%- if salt.pkg.version('openldap-servers') %}
svc_{{ stigId }}-openldapEnabled:
  service.disabled:
    - name: 'slapd'

svc_{{ stigId }}-openldapRunning:
  service.dead:
    - name: 'slapd'

pkg_{{ stigId }}-remove:
  pkg.removed:
    - name: 'openldap-servers'
{%- else %}
notice_{{ stigId }}-notPresent:
  cmd.run:
    - name: 'echo "The openldap-servers subsystem is not installed"'
{%- endif %}
