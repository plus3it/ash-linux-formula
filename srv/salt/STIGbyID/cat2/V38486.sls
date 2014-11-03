# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38486
# Finding ID:	V-38486
# Version:	RHEL-06-000505
# Finding Level:	Medium
#
#     Operating system backup is a critical step in maintaining data 
#     assurance and availability. System-level information includes 
#     system-state information, operating system and application software, 
#     and licenses. Backups must be consistent with organizational recovery 
#     time and recovery point objectives.
#
#  CCI: CCI-000537
#  NIST SP 800-53 :: CP-9 (b)
#  NIST SP 800-53A :: CP-9.1 (v)
#  NIST SP 800-53 Revision 4 :: CP-9 (b)
#
############################################################

script_V38486-describe:
  cmd.script:
  - source: salt://STIGbyID/cat2/files/V38486.sh

cmd_V38486-NotTechnical:
  cmd.run:
  - name: 'echo "Not a technical/enforcible control"'
