# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38481
# Finding ID:   V-38481
# Version:      RHEL-06-000011
# Finding Level:        Medium
#
#     System security patches and updates must be installed and up-to-date.
#     Installing software updates is a fundamental mitigation against the
#     exploitation of publicly-known vulnerabilities.
#
#  CCI: CCI-001233
#  NIST SP 800-53 :: SI-2 (2)
#  NIST SP 800-53A :: SI-2 (2).1 (ii)
#  NIST SP 800-53 Revision 4 :: SI-2 (2)
#
############################################################

script_V38481-describe:
  cmd.script:
    - source: salt://ash-linux/STIGbyID/cat2/files/V38481.sh
    - cwd: '/root'

cmd_V38481-chkSubscribe:
  cmd.run:
    - name: 'echo "Subscribed to yum service"'
    - unless: 'yum repolist | grep "repolist: 0"'

cmd_V38481-lastUpdate:
  cmd.run:
    - name: "printf 'System last updated: ' ; rpm -q `rpm -qa -last | awk 'END {print $1}'` --qf '%{installtime:date}\n'"
    - unless: 'yum repolist | grep "repolist: 0"'

pkg_V38481-upgrades:
  module.run:
    - name: pkg.list_upgrades
