# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38606
# Finding ID:	V-38606
# Version:	RHEL-06-000222
# Finding Level:	Medium
#
#     The tftp-server package must not be installed. Removing the 
#     "tftp-server" package decreases the risk of the accidental (or 
#     intentional) activation of tftp services.
#
#  CCI: CCI-000381
#  NIST SP 800-53 :: CM-7
#  NIST SP 800-53A :: CM-7.1 (ii)
#  NIST SP 800-53 Revision 4 :: CM-7 a
#
############################################################

script_V38606-describe:
  cmd.script:
    - source: salt://STIGbyID/cat2/files/V38606.sh

{% if salt['pkg.version']('tftp-server') %}
svc_V38606-tfptd:
  service.disabled:
    - name: 'tftp-server'
{% endif %}

pkg_V38606-tftpd:
  pkg.purged:
    - name: 'tftp-server'
