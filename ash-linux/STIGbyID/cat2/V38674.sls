# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38674
# Finding ID:	V-38674
# Version:	RHEL-06-000290
# Finding Level:	Medium
#
#     X Windows must not be enabled unless required. Unnecessary services 
#     should be disabled to decrease the attack surface of the system.
#
#  CCI: CCI-001436
#  NIST SP 800-53 :: AC-17 (8)
#  NIST SP 800-53A :: AC-17 (8).1 (ii)
#
############################################################

script_V38674-describe:
  cmd.script:
    - source: salt://ash-linux/STIGbyID/cat2/files/V38674.sh
    - cwd: '/root'

{% if salt['file.search']('/etc/inittab', '^id:5:') %}
cmd_V38674-x11warn:
  cmd.run:
    - name: 'echo "Default run-level enables X11. Will be disabled at next system-boot."'
{% endif %}
file_V38674-repl:
  file.replace:
    - name: '/etc/inittab'
    - pattern: '^id:.*$'
    - repl: 'id:3:initdefault:'

