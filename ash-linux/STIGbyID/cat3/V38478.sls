# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38478
# Finding ID:	V-38478
# Version:	RHEL-06-000009
# Finding Level:	Low
#
#     Although systems management and patching is extremely important to 
#     system security, management by a system outside the enterprise 
#     enclave is not desirable for some environments. However, if the 
#     system is being managed by RHN or RHN Satellite Server the "rhnsd" 
#     daemon can remain on. 
#
#  CCI: CCI-000382
#  NIST SP 800-53 :: CM-7
#  NIST SP 800-53A :: CM-7.1 (iii)
#  NIST SP 800-53 Revision 4 :: CM-7 b
#
############################################################

script_V38478-describe:
  cmd.script:
    - source: salt://STIGbyID/cat3/files/V38478.sh

{% if salt['pkg.version']('rhnsd') %}
# Ensure rhnsd service is disabled and stopped
svc_V38478-rhnsdDisabled:
  service.disabled:
    - name: 'rhnsd'

svc_V38478-rhnsdDead:
  service.dead:
    - name: 'rhnsd'
{% else %}
cmd_V38478-notice:
  cmd.run:
    - name: 'echo "RHNSD service not installed. No relevant findings possible."'
{% endif %}
