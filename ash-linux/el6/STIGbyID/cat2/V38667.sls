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
#  CCI: CCI-001263
#  NIST SP 800-53 :: SI-4 (5)
#  NIST SP 800-53A :: SI-4 (5).1 (ii)
#
############################################################################

{%- set stig_id = '38667' %}
{%- set helperLoc = 'ash-linux/el6/STIGbyID/cat2/files' %}
{%- set selCfgFile = '/etc/sysconfig/selinux' %}
{%- set grubCfgFile = '/boot/grub/grub.conf' %}

script_V{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/V{{ stig_id }}.sh
    - cwd: '/root'

# Alter the running system-state
{%- if salt.pkg.version('policycoreutils-python') %}

sel_V{{ stig_id }}:
  selinux:
    - mode
    - name: 'Enforcing'

{%- endif %}

# Verify that the reboot system-state is acceptable
{%- if salt.file.file_exists(selCfgFile) %}

  {%- if salt.file.search(selCfgFile, '^SELINUX=disabled') %}

file_V{{ stig_id }}-enableSEL:
  file.replace:
    - name: '{{ selCfgFile }}'
    - pattern: '^SELINUX=disabled'
    - repl: '^SELINUX=permissive'

status_v{{ stig_id }}:
  cmd.run:
    - name: 'echo "NOTICE: SELinux found disabled. Changing to \"Permissive\". Reboot required to take effect"'

  {%- else %}

status_v{{ stig_id }}:
  cmd.run:
    - name: 'echo "Info: SELinux already enabled to at least a level of Permissive"'

  {%- endif %}

{%- endif %}

# Make sure AIDE is installed
pkg_V{{ stig_id }}-aide:
  pkg.installed:
    - name: aide

# Ensure audit service is enabled and running
svc_V{{ stig_id }}-auditEnabled:
  service.enabled:
    - name: 'auditd'

svc_V{{ stig_id }}-auditRunning:
  service.running:
    - name: 'auditd'
