# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-57569
# Finding ID:	V-57569
# Version:	RHEL-06-000528
# Finding Level:	Medium
#
#     Allowing users to execute binaries from world-writable 
#     directories such as "/tmp" should never be necessary in normal 
#     operation and can expose the system to potential compromise.
#
# CCI: CCI-000381
# NIST SP 800-53 :: CM-7
# NIST SP 800-53A :: CM-7.1 (ii)
# NIST SP 800-53 Revision 4 :: CM-7 a
#
############################################################

script_V57569-describe:
  cmd.script:
  - source: salt://STIGbyID/cat2/files/V57569.sh

# Ingest list of mounted filesystesm into a searchable-structure
{% set activeMntStream = salt['mount.active']('extended=true') %}

{% if '/tmp' in activeMntStream %}
notify_V57569:
  cmd.run:
  - name: 'echo "/tmp is on its own partition"'
{% else %}
notify_V57569:
  cmd.run:
  - name: 'echo "/tmp is not on its own partition"'
{% endif %}
