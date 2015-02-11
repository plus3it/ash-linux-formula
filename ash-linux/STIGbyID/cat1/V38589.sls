# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38589
# Finding ID:	V-38589
# Version:	RHEL-06-000211
# Finding Level:	High
#
#     The telnet daemon must not be running. The telnet protocol uses 
#     unencrypted network communication, which means that data from the 
#     login session, including passwords and all other information 
#     transmitted during the session, can be stolen ...
#
############################################################

script_V38589-describe:
  cmd.script:
    - source: salt://STIGbyID/cat1/files/V38589.sh
    - cwd: /root

# See if the telnet server package is even installed...
{% if salt['pkg.version']('telnet-server') %}
  # If installed, and enabled, disable it
  {% if salt['service.enabled']('telnet') %}
svc_V38589-telnetDisabled:
  service.disabled:
    - name: 'telnet'

svc_V38589-telnetDead:
  service.dead:
    - name: 'telnet'

notice_V38589-disableTelnet:
  cmd.run:
    - name: 'echo "The ''telnet'' service has been disabled"'
    - unless: svc_V38589-telnetDisabled
  # If installed but disabled, make a note of it
  {% else %}
notice_V38589-disableTelnet:
  cmd.run:
    - name: 'echo "The ''telnet'' service already disabled"'
  {% endif %}
# Otherwise, just notify that telnet service isn't even present
{% else %}
notice_V38589-disableTelnet:
  cmd.run:
    - name: 'echo "The ''telnet-server'' package is not installed"'
{% endif %}
