# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38597
# Finding ID:	V-38597
# Version:	RHEL-06-000079
# Finding Level:	Medium
#
#     The system must limit the ability of processes to have simultaneous 
#     write and execute access to memory. ExecShield uses the segmentation 
#     feature on all x86 systems to prevent execution in memory higher than 
#     a certain address. It writes an address as a limit in the code 
#     segment descriptor, to control ...
#
#  CCI: CCI-000366
#  NIST SP 800-53 :: CM-6 b
#  NIST SP 800-53A :: CM-6.1 (iv)
#  NIST SP 800-53 Revision 4 :: CM-6 b
#
############################################################

script_V38597-describe:
  cmd.script:
    - source: salt://ash-linux/STIGbyID/cat2/files/V38597.sh

{% if salt['file.search']('/etc/sysctl.conf', 'kernel.exec-shield') %}
file_V38597-repl:
  file.replace:
    - name: '/etc/sysctl.conf'
    - pattern: '^kernel.exec-shield.*$'
    - repl: 'kernel.exec-shield = 1'
{% else %}
file_V38597-append:
  file.append:
    - name: '/etc/sysctl.conf'
    - text:
      - ' '
      - '# Enable exec-shield (per STIG V-38597)'
      - 'kernel.exec-shield = 1'
{% endif %}
