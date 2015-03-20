# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38586
# Finding ID:	V-38586
# Version:	RHEL-06-000069
# Finding Level:	Medium
#
#     The system must require authentication upon booting into single-user 
#     and maintenance modes. This prevents attackers with physical access 
#     from trivially bypassing security on the machine and gaining root 
#     access. Such accesses are further prevented by configuring the 
#     bootloader password.
#
#  CCI: CCI-000213
#  NIST SP 800-53 :: AC-3
#  NIST SP 800-53A :: AC-3.1
#  NIST SP 800-53 Revision 4 :: AC-3
#
############################################################

script_V38586-describe:
  cmd.script:
    - source: salt://ash-linux/STIGbyID/cat2/files/V38586.sh
    - cwd: '/root'

# Conditional replace or append
{%- if salt['file.search']('/etc/sysconfig/init', '^SINGLE') %}
file_V38586-repl:
  file.replace:
    - name: '/etc/sysconfig/init'
    - pattern: '^SINGLE.*$'
    - repl: 'SINGLE=/sbin/sulogin' 
{%- else %}
file_V38586-append:
  file.append:
    - name: '/etc/sysconfig/init'
    - text:
      - ' '
      - '# Require root password for single-user access (per STIG V-38586)'
      - 'SINGLE=/sbin/sulogin'
{%- endif %}
