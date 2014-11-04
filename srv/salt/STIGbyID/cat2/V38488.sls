# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38488
# Finding ID:	V-38488
# Version:	RHEL-06-000504
# Finding Level:	Medium
#
#     Operating system backup is a critical step in maintaining data 
#     assurance and availability. User-level information is data generated 
#     by information system and/or application users. Backups shall be 
#     consistent with organizational recovery time and recovery point 
#     objectives.
#
#  CCI: CCI-000535
#  NIST SP 800-53 :: CP-9 (a)
#  NIST SP 800-53A :: CP-9.1 (iv)
#  NIST SP 800-53 Revision 4 :: CP-9 (a)
#
############################################################

script_V38488-describe:
  cmd.script:
  - source: salt://STIGbyID/cat2/files/V38488.sh

cmd_V38488-NotTechnical:
  cmd.run:
  - name: 'echo "Not a technical/enforcible control"'
