# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38667
# Finding ID:	V-38667
# Version:	RHEL-06-000285
# Finding Level:	Medium
#
#     Adding host-based intrusion detection tools can provide the 
#     capability to automatically take actions in response to malicious 
#     behavior, which can provide additional agility in reacting to network 
#     threats. These tools also often include a reporting capability to 
#     provide network awareness of system, which may not otherwise exist in 
#     an organization's systems management regime. 
#
############################################################################

script_V38667-describe:
  cmd.script:
  - source: salt://STIGbyID/cat2/files/V38667.sh

# Alter the running system-state
{% if salt['pkg.version']('policycoreutils-python') %}
sel_V38667:
  selinux:
  - mode
  - name: 'Enforcing'
{% endif %}

# Verify that the reboot system-state is acceptable
{% if salt['file.search']('/etc/sysconfig/selinux', '^SELINUX=disabled') %}
file_V38667-enableSEL:
  file.replace:
  - name: '/etc/sysconfig/selinux'
  - pattern: '^SELINUX=disabled'
  - repl: '^SELINUX=permissive'

status_v38667:
  cmd.run:
  - name: 'echo "NOTICE: SELinux found disabled. Changing to \"Permissive\". Reboot required to take effect"'

{% else %}
status_v38667:
  cmd.run:
  - name: 'echo "Info: SELinux already enabled at at least a level of Permissive"'

{% endif %}

## pkg_V38667-aide:
##   pkg.installed:
##   - name: aide

