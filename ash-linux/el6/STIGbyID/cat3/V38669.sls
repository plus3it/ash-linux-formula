# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38669
# Finding ID:	V-38669
# Version:	RHEL-06-000287
# Finding Level:	Low
#
#     The postfix service must be enabled for mail delivery. Local mail
#     delivery is essential to some system maintenance and notification
#     tasks.
#
#  CCI: CCI-000366
#  NIST SP 800-53 :: CM-6 b
#  NIST SP 800-53A :: CM-6.1 (iv)
#  NIST SP 800-53 Revision 4 :: CM-6 b
#
############################################################

{%- set stigId = 'V38669' %}
{%- set helperLoc = 'ash-linux/el6/STIGbyID/cat3/files' %}

script_{{ stigId }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stigId }}.sh
    - cwd: /root

{%- set wantedPkg = 'postfix' %}

{%- if not salt.pkg.version(wantedPkg) %}
notify_{{ stigId }}-noPostfix:
  cmd.run:
    - name: 'echo "Postfix not installed"'
  {%- if salt.pkg.version('sendmail') %}
notify_{{ stigId }}-sendmail:
  cmd.run:
    - name: 'echo "Sendmail installed instead of postfix"'
  {%- else %}
notify_{{ stigId }}-postfix:
  cmd.run:
    - name: 'echo "Attempting to install missing {{ wantedPkg }} package."'

pkg_{{ stigId }}-postfix:
  pkg.installed:
    - name: '{{ wantedPkg }}'
    - retry:
        attempts: 10
        until: True
        interval: 10
        splay: 10

svc_{{ stigId }}-postfixEnabled:
  service.enabled:
    - name: '{{ wantedPkg }}'
    - retry:
        attempts: 5
        until: True
        interval: 10
        splay: 10

svc_{{ stigId }}-postfixRunning:
  service.running:
    - name: '{{ wantedPkg }}'
    - retry:
        attempts: 20
        until: True
        interval: 2
        splay: 10    
  {%- endif %}
{%- else %}
# Ensure postfix service is enabled and running
svc_{{ stigId }}-postfixEnabled:
  service.enabled:
    - name: '{{ wantedPkg }}'
    - retry:
        attempts: 5
        until: True
        interval: 10
        splay: 10

svc_{{ stigId }}-postfixRunning:
  service.running:
    - name: '{{ wantedPkg }}'
    - retry:
        attempts: 20
        until: True
        interval: 2
        splay: 10    
{%- endif %}
