# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38650
# Finding ID:	V-38650
# Version:	RHEL-06-000268
# Finding Level:	Low
#
#     The rdisc service must not be running. General-purpose systems 
#     typically have their network and routing information configured 
#     statically by a system administrator. Workstations or some 
#     special-purpose systems often use DHCP (instead of IRDP) to retrieve 
#     dynamic network configuration information. 
#
#  CCI: CCI-000382
#  NIST SP 800-53 :: CM-7
#  NIST SP 800-53A :: CM-7.1 (iii)
#  NIST SP 800-53 Revision 4 :: CM-7 b
#
############################################################
{%- set stigId = 'V38650' %}
{%- set helperLoc = 'ash-linux/el6/STIGbyID/cat3/files' %}

script_{{ stigId }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stigId }}.sh
    - cwd: /root

{%- if salt.pkg.version('iputils') %}
svc_{{ stigId }}-rdiscEnabled:
  service.disabled:
    - name: 'rdisc'

svc_{{ stigId }}-rdiscRunning:
  service.dead:
    - name: 'rdisc'
{%- else %}
notice_{{ stigId }}-notPresent:
  cmd.run:
    - name: 'echo "The rdisc subsystem is not installed"'
{%- endif %}
