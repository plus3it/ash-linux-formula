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

script_V{{ stig_id }}-describe:
  cmd.script:
    - source: salt://ash-linux/STIGbyID/cat2/files/V{{ stig_id }}.sh
    - cwd: '/root'

# Alter the running system-state
{%- if salt['pkg.version']('policycoreutils-python') %}

sel_V{{ stig_id }}:
  selinux:
    - mode
    - name: 'Enforcing'

{%- endif %}

# Verify that the reboot system-state is acceptable
{%- if salt['file.file_exists']('/etc/sysconfig/selinux') %}

  {%- if salt['file.search']('/etc/sysconfig/selinux', '^SELINUX=disabled') %}

file_V{{ stig_id }}-enableSEL:
  file.replace:
    - name: '/etc/sysconfig/selinux'
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

#############################
# Enable audit at kernel load
{%- if salt['file.search']('/boot/grub/grub.conf', 'kernel') and not salt['file.search']('/boot/grub/grub.conf', 'kernel.*audit=1') %}

file_V{{ stig_id }}-repl:
  file.replace:
    - name: '/boot/grub/grub.conf'
    - pattern: '(?P<srctok>kernel.*$)'
    - repl: '\g<srctok> audit=1'

{%- else %}

status_V{{ stig_id }}:
  cmd.run:
    - name: 'echo "Auditing already enabled at boot"'

{%- endif %}
