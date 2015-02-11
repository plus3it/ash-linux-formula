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

script_V38591-describe:
  cmd.script:
  - source: salt://STIGbyID/cat1/files/V38591.sh
  - cwd: /root

{% set chkPkg = 'rsh-server' %}

{% if salt['pkg.version'](chkPkg) %}
pkg_V38591-removeRsh:
  pkg.removed:
  - name: '{{ chkPkg }}'
{% else %}
pkg_V38591-removeRsh:
  cmd.run:
  - name: 'echo "The ''{{ chkPkg }}'' package is not installed"'
{% endif %}
