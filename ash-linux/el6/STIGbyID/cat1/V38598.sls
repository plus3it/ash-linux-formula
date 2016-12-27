# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38598
# Finding ID:	V-38598
# Version:	RHEL-06-000216
# Finding Level:	High
#
#     The rexecd service must not be running. The rexec service uses 
#     unencrypted network communications, which means that data from the 
#     login session, including passwords and all other information 
#     transmitted during the session, can be stolen by ...
#
############################################################

{%- set stigId = 'V38598' %}
{%- set helperLoc = 'ash-linux/el6/STIGbyID/cat1/files' %}
{%- set svcNam = 'rexec' %}

script_{{ stigId }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stigId }}.sh
    - cwd: /root

# See if the {{ svcNam }} server package is even installed...
{%- if salt.pkg.version('rsh-server') %}
  # If installed, and enabled, disable it
  {%- if salt.service.enabled(svcNam) %}
svc_{{ stigId }}-{{ svcNam }}Disabled:
  service.disabled:
    - name: '{{ svcNam }}'

svc_{{ stigId }}-{{ svcNam }}Dead:
  service.dead:
    - name: '{{ svcNam }}'

notice_{{ stigId }}-disable{{ svcNam }}:
  cmd.run:
    - name: 'echo "The ''{{ svcNam }}'' service has been disabled"'
    - unless: svc_{{ stigId }}-{{ svcNam }}Disabled
  # If installed but disabled, make a note of it
  {%- else %}
notice_{{ stigId }}-disable{{ svcNam }}:
  cmd.run:
    - name: 'echo "The ''{{ svcNam }}'' service already disabled"'
  {%- endif %}
# Otherwise, just notify that {{ svcNam }} service isn't even present
{%- else %}
notice_{{ stigId }}-disable{{ svcNam }}:
  cmd.run:
    - name: 'echo "The ''rsh-server'' package is not installed"'
{%- endif %}
