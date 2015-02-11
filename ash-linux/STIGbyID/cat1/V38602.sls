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

script_V38602-describe:
  cmd.script:
    - source: salt://STIGbyID/cat1/files/V38602.sh
    - cwd: /root

{% set rSvcName = 'rlogin' %}

# See if the rsh server package is even installed...
{% if salt['pkg.version']('rsh-server') %}
  # If installed, and enabled, disable it
  {% if salt['service.enabled'](rSvcName) %}
svc_V38602-{{ rSvcName }}Disabled:
  service.disabled:
    - name: '{{ rSvcName }}'

svc_V38602-{{ rSvcName }}Dead:
 service.dead:
    - name: '{{ rSvcName }}'

notice_V38602-disable{{ rSvcName }}:
  cmd.run:
    - name: 'echo "The ''{{ rSvcName }}'' service has been disabled"'
    - unless: svc_V38602-{{ rSvcName }}Disabled
  # If installed but disabled, make a note of it
  {% else %}
notice_V38602-disable{{ rSvcName }}:
  cmd.run:
    - name: 'echo "The ''{{ rSvcName }}'' service already disabled"'
  {% endif %}
# Otherwise, just notify that rsh service isn't even present
{% else %}
notice_V38602-disable{{ rSvcName }}:
  cmd.run:
    - name: 'echo "The ''rsh-server'' package is not installed"'
{% endif %}
