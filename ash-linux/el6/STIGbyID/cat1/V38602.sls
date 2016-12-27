#!/bin/sh
#
# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38602
# Finding ID:	V-38602
# Version:	RHEL-06-000218
# Finding Level:	High
#
#     The rlogind service must not be running. The rlogin service uses 
#     unencrypted network communications, which means that data from the 
#     login session, including passwords and all other information 
#     transmitted during the session, can be stolen ...
#
############################################################

{%- set stigId = 'V38602' %}
{%- set helperLoc = 'ash-linux/el6/STIGbyID/cat1/files' %}

script_{{ stigId }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stigId }}.sh
    - cwd: /root

{%- set rSvcName = 'rlogin' %}

# See if the rsh server package is even installed...
{%- if salt.pkg.version('rsh-server') %}
  # If installed, and enabled, disable it
  {%- if salt.service.enabled(rSvcName) %}
svc_{{ stigId }}-{{ rSvcName }}Disabled:
  service.disabled:
    - name: '{{ rSvcName }}'

svc_{{ stigId }}-{{ rSvcName }}Dead:
 service.dead:
    - name: '{{ rSvcName }}'

notice_{{ stigId }}-disable{{ rSvcName }}:
  cmd.run:
    - name: 'echo "The ''{{ rSvcName }}'' service has been disabled"'
    - unless: svc_{{ stigId }}-{{ rSvcName }}Disabled
  # If installed but disabled, make a note of it
  {%- else %}
notice_{{ stigId }}-disable{{ rSvcName }}:
  cmd.run:
    - name: 'echo "The ''{{ rSvcName }}'' service already disabled"'
  {%- endif %}
# Otherwise, just notify that rsh service isn't even present
{%- else %}
notice_{{ stigId }}-disable{{ rSvcName }}:
  cmd.run:
    - name: 'echo "The ''rsh-server'' package is not installed"'
{%- endif %}
