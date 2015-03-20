# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38621
# Finding ID:	V-38621
# Version:	RHEL-06-000248
# Finding Level:	Medium
#
#     The system clock must be synchronized to an authoritative DoD time 
#     source. Synchronizing with an NTP server makes it possible to collate 
#     system logs from multiple sources or correlate computer events with 
#     real time events. Using a trusted NTP server provided by your ...
#
#  CCI: CCI-000160
#  NIST SP 800-53 :: AU-8 (1)
#  NIST SP 800-53A :: AU-8 (1).1 (iii)
#
############################################################

script_V38621-describe:
  cmd.script:
    - source: salt://ash-linux/STIGbyID/cat2/files/V38621.sh
    - cwd: '/root'

{%- if not salt['pkg.version']('ntp') %}
pkg_V38621-ntp:
  pkg.installed:
    - name: 'ntp'
{%- endif %}

cmd_V38621-notice:
  cmd.run:
    - name: 'echo "Manual remediation required"'
