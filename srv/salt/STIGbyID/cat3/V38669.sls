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

script_V38669-describe:
  cmd.script:
  - source: salt://STIGbyID/cat3/files/V38669.sh

{% if not salt['pkg.version']('postfix') %}
notify_V38669-noPostfix:
  cmd.run:
  - name: 'echo "Postfix not installed"'
  {% if salt['pkg.version']('sendmail') %}
notify_V38669-sendmail:
  cmd.run:
  - name: 'echo "Sendmail installed instead of postfix"'
  {% endif %}
{% else %}
# Ensure postfix service is enabled and running
svc_V38669-postfixEnabled:
  service.enabled:
  - name: 'postfix'

svc_V38669-postfixRunning:
  service.running:
  - name: 'postfix'
{% endif %}

