# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38648
# Finding ID:	V-38648
# Version:	RHEL-06-000267
# Finding Level:	Low
#
#     The qpidd service must not be running. The qpidd service is 
#     automatically installed when the "base" package selection is selected 
#     during installation. The qpidd service listens for network 
#     connections which increases the attack surface of the system. If the 
#     system is not intended to receive AMQP traffic then the "qpidd" 
#     service is not needed and should be disabled or removed.
#
############################################################

script_V38648-describe:
  cmd.script:
  - source: salt://STIGbyID/cat3/files/V38648.sh

{% if salt['pkg.version']('qpid-cpp-server') %}
svc_V38648-qpiddEnabled:
  service.disabled:
  - name: 'qpidd'

svc_V38648-qpiddRunning:
 service.dead:
  - name: 'qpidd'
{% else %}
notice_V38648-notPresent:
   cmd.run:
   - name: 'echo "The qpid subsystem is not installed"'
{% endif %}

