# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38676
# Finding ID:	V-38676
# Version:	RHEL-06-000291
# Finding Level:	Low
#
#     The xorg-x11-server-common (X Windows) package must not be installed, 
#     unless required. Unnecessary packages should not be installed to 
#     decrease the attack surface of the system.
#
#
############################################################

script_V38676-describe:
  cmd.script:
  - source: salt://STIGbyID/cat3/files/V38676.sh

{% if not salt['pkg.version']('xorg-x11-server-common') %}
notify_V38676-noPostfix:
  cmd.run:
  - name: 'echo "X Windows package not installed"'
{% endif %}
