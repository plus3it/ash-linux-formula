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

script_V38684-describe:
  cmd.script:
  - source: salt://STIGbyID/cat3/files/V38684.sh

# Generate a user-list to iterate
{% for user in salt['user.getent']('') %}
{% set ID = user['name'] %}
# ganked from 681: modify to pull user['expire'] value...
{% if not salt['file.search']('/etc/group', ':' + user['gid']|string() + ':' ) %}
notify_V38684-{{ ID }}:
  cmd.run:
  - name: 'echo "The {{ ID }} users GID [{{ user['gid'] }}] is not mapped in /etc/group."'
{% endif %}
{% endfor %}

# Probably want output indicating that no unmapped GIDs were found...
