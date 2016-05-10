# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38603
# Finding ID:	V-38603
# Version:	RHEL-06-000220
# Finding Level:	Medium
#
#     The ypserv package must not be installed. Removing the "ypserv" 
#     package decreases the risk of the accidental (or intentional) 
#     activation of NIS or NIS+ services.
#
#  CCI: CCI-000381
#  NIST SP 800-53 :: CM-7
#  NIST SP 800-53A :: CM-7.1 (ii)
#  NIST SP 800-53 Revision 4 :: CM-7 a
#
############################################################

{%- set stigId = 'V38603' %}
{%- set helperLoc = 'ash-linux/el6/STIGbyID/cat2/files' %}

script_{{ stigId }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stigId }}.sh
    - cwd: '/root'

pkg_{{ stigId }}:
  pkg.purged:
    - pkgs: 
      - yp-tools
      - ypbind
      - ypserv
