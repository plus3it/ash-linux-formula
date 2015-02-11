# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38466
# Finding ID:	V-38466
# Version:	RHEL-06-000046
# Finding Level:	Medium
#
#     Library files must be owned by root. Files from shared library 
#     directories are loaded into the address space of processes (including 
#     privileged ones) or of the kernel itself at runtime. Proper ownership 
#     is necessary to protect the ...
#
#  CCI: CCI-001499
#  NIST SP 800-53 :: CM-5 (6)
#  NIST SP 800-53A :: CM-5 (6).1
#  NIST SP 800-53 Revision 4 :: CM-5 (6)
#
############################################################

script_V38466-describe:
  cmd.script:
    - source: salt://STIGbyID/cat2/files/V38466.sh

file_V38466-lib:
  file.directory:
    - name: /lib
    - user: root
    - recurse:
      - user

file_V38466-lib64:
  file.directory:
    - name: /lib64
    - user: root
    - recurse:
      - user

file_V38466-ulib:
  file.directory:
    - name: /usr/lib
    - user: root
    - recurse:
      - user

file_V38466-ulib64:
  file.directory:
    - name: /usr/lib64
    - user: root
    - recurse:
      - user
