# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38587
# Finding ID:	V-38587
# Version:	RHEL-06-000206
# Finding Level:	High
#
#     The telnet-server package must not be installed. Removing the 
#     "telnet-server" package decreases the risk of the unencrypted telnet 
#     service's accidental (or intentional) activation.  Mitigation: If
#     the telnet-server package is configured to only allow encrypted 
#     sessions, such as with Kerberos or the use of encrypted network 
#     tunnels, the risk of exposing sensitive information is mitigated. 
#
############################################################

{%- set stigId = 'V38587' %}
{%- set helperLoc = 'ash-linux/el6/STIGbyID/cat1/files' %}
{%- set chkPkg = 'telnet-server' %}

script_{{ stigId }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stigId }}.sh
    - cwd: /root

{%- if salt.pkg.version(chkPkg) %}
pkg_{{ stigId }}-removeTelnet:
  pkg.removed:
    - name: '{{ chkPkg }}'
{%- else %}
pkg_{{ stigId }}-removeTelnet:
  cmd.run:
    - name: 'echo "The ''{{ chkPkg }}'' package is not installed"'
{%- endif %}
