# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38594
# Finding ID:	V-38594
# Version:	RHEL-06-000214
# Finding Level:	High
#
#     The rshd service must not be running. The rsh service uses 
#     unencrypted network communications, which means that data from the 
#     login session, including passwords and all other information 
#     transmitted during the session, can be stolen by ...
#
############################################################

script_V38594-describe:
  cmd.script:
    - source: salt://STIGbyID/cat1/files/V38594.sh
    - cwd: /root

# See if the rsh server package is even installed...
{% if salt['pkg.version']('rsh-server') %}
  # If installed, and enabled, disable it
  {% if salt['service.enabled']('rsh') %}
svc_V38594-rshDisabled:
  service.disabled:
    - name: 'rsh'

svc_V38594-rshDead:
  service.dead:
    - name: 'rsh'

notice_V38594-disableTelnet:
  cmd.run:
    - name: 'echo "The ''rsh'' service has been disabled"'
    - unless: svc_V38594-rshDisabled
  # If installed but disabled, make a note of it
  {% else %}
notice_V38594-disableTelnet:
  cmd.run:
    - name: 'echo "The ''rsh'' service already disabled"'
  {% endif %}
# Otherwise, just notify that rsh service isn't even present
{% else %}
notice_V38594-disableTelnet:
  cmd.run:
    - name: 'echo "The ''rsh-server'' package is not installed"'
{% endif %}
