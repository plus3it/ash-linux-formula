# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38528
# Finding ID:	V-38528
# Version:	RHEL-06-000088
# Finding Level:	Low
#
#     The system must log Martian packets. The presence of "martian" 
#     packets (which have impossible addresses) as well as spoofed packets, 
#     source-routed packets, and redirects could be a sign of nefarious 
#     network activity. Logging these packets enables this activity to be 
#     detected. 
#
#  CCI: CCI-000366
#  NIST SP 800-53 :: CM-6 b
#  NIST SP 800-53A :: CM-6.1 (iv)
#  NIST SP 800-53 Revision 4 :: CM-6 b
#
############################################################

{%- set stigId = 'V38528' %}
{%- set helperLoc = 'ash-linux/el6/STIGbyID/cat3/files' %}
{%- set parmName = 'net.ipv4.conf.all.log_martians' %}
{%- set parmVal = '1' %}

script_{{ stigId }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stigId }}.sh
    - cwd: /root

{%- if salt.sysctl.get(parmName) == parmVal %}
sysctl_{{ stigId }}-logMartians:
  cmd.run:
    - name: 'echo "Logging of Martian packets already enabled"'
{%- else %}
sysctl_{{ stigId }}-logMartians:
  sysctl.present:
    - name: '{{ parmName }}'
    - value: '{{ parmVal }}'
{%- endif %}
