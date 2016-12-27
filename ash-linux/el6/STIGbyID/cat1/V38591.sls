# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38591
# Finding ID:	V-38591
# Version:	RHEL-06-000213
# Finding Level:	High
#
#     The rsh-server package must not be installed. The "rsh-server" 
#     package provides several obsolete and insecure network services. 
#     Removing it decreases the risk of those services' accidental (or 
#     intentional) activation.
#
############################################################

{%- set stigId = 'V38591' %}
{%- set helperLoc = 'ash-linux/el6/STIGbyID/cat1/files' %}
{%- set chkPkg = 'rsh-server' %}

script_{{ stigId }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stigId }}.sh
    - cwd: /root

{%- if salt.pkg.version(chkPkg) %}
pkg_{{ stigId }}-removeRsh:
  pkg.removed:
    - name: '{{ chkPkg }}'
{%- else %}
pkg_{{ stigId }}-removeRsh:
  cmd.run:
    - name: 'echo "The ''{{ chkPkg }}'' package is not installed"'
{%- endif %}
