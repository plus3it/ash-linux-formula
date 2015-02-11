# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38685
# Finding ID:	V-38685
# Version:	RHEL-06-000297
# Finding Level:	Low
#
#     Temporary accounts must be provisioned with an expiration date. When 
#     temporary accounts are created, there is a risk they may remain in 
#     place and active after the need for them no longer exists. Account 
#     expiration greatly reduces the risk of accounts being misused or
#     hijacked.
#
#  CCI: CCI-000016
#  NIST SP 800-53 :: AC-2 (2)
#  NIST SP 800-53A :: AC-2 (2).1 (ii)
#  NIST SP 800-53 Revision 4 :: AC-2 (2)
#
############################################################

script_V38685-describe:
  cmd.script:
  - source: salt://STIGbyID/cat3/files/V38685.sh

notify_V38685-generic:
  cmd.run:
  - name: 'printf "******************************************\n** This is an informational test, only! **\n******************************************\nTest cannot auto-ID temporary accounts:\n  Each locally-managed user will be queried.\n  Expiry settings will be enumerated but not\n  modified\n"'

# Generate a user-list to iterate
{% for user in salt['user.getent']('') %}
  {% set ID = user['name'] %}
  {% set ShadowData = salt['shadow.info'](ID) %}

  {% if ShadowData.expire == -1 %}
notify_V38685-{{ ID }}:
  cmd.run:
  - name: 'echo "Userid ''{{ ID }}'' is not set to expire"'
  {% else %}
notify_V38685-{{ ID }}:
  cmd.run:
  - name: 'echo "Userid ''{{ ID }}'' is set to expire [{{ ShadowData.expire }}]"'
  {% endif %}
{% endfor %}
