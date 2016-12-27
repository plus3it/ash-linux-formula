# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38687
# Finding ID:	V-38687
# Version:	RHEL-06-000321
# Finding Level:	Low
#
#     The system must provide VPN connectivity for communications over 
#     untrusted networks. Providing the ability for remote users or systems 
#     to initiate a secure VPN connection protects information when it is 
#     transmitted over a wide area network.
#
#  CCI: CCI-001130
#  NIST SP 800-53 :: SC-9
#  NIST SP 800-53A :: SC-9.1
#
############################################################
{%- set stigId = 'V38687' %}
{%- set helperLoc = 'ash-linux/el6/STIGbyID/cat3/files' %}
{%- set swanPkg = 'libreswan' %}

script_{{ stigId }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stigId }}.sh
    - cwd: /root

{%- if salt.pkg.version(swanPkg) %}
notify_{{ stigId }}-{{ swanPkg }}:
  cmd.run:
    - name: 'echo "OpenSwan utilities already installed"'
{%- else %}
installed_{{ stigId }}-{{ swanPkg }}:
  pkg.installed:
    - name: '{{ swanPkg }}'

notify_{{ stigId }}-openSwan:
  cmd.run:
    - name: 'echo "Installed OpenSwan utilities"'
    - unless: 'installed_{{ stigId }}-{{ swanPkg }}'
{%- endif %}
