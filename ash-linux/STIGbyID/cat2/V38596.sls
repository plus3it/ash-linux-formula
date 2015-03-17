# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38596
# Finding ID:	V-38596
# Version:	RHEL-06-000078
# Finding Level:	Medium
#
#     The system must implement virtual address space randomization. 
#     Address space layout randomization (ASLR) makes it more difficult for 
#     an attacker to predict the location of attack code he or she has 
#     introduced into a process's address space during an attempt at ...
#
#  CCI: CCI-000366
#  NIST SP 800-53 :: CM-6 b
#  NIST SP 800-53A :: CM-6.1 (iv)
#  NIST SP 800-53 Revision 4 :: CM-6 b
#
############################################################

script_V38596-describe:
  cmd.script:
    - source: salt://ash-linux/STIGbyID/cat2/files/V38596.sh
    - cwd: '/root'

{%- if salt['file.search']('/etc/sysctl.conf', '^kernel.randomize_va_space')
 %}
file_V38596-repl:
  file.replace:
    - name: '/etc/sysctl.conf'
    - pattern: '^kernel.randomize_va_space.*$'
    - repl: 'kernel.randomize_va_space = 2'
{%- else %}
file_V38596-append:
  file.append:
    - name: '/etc/sysctl.conf'
    - text:
      - ' '
      - '# enable ASLR (per STIG V-38596)'
      - 'kernel.randomize_va_space = 2'
{%- endif %}
