# Finding ID:	RHEL-07-020211
# Version:	RHEL-07-020211_rule
# SRG ID:	SRG-OS-000445-GPOS-00199
# Finding Level:	high
#
# Rule Summary:
#	The operating system must enable the SELinux targeted policy.
#
# CCI-002165 CCI-002696
#    NIST SP 800-53 Revision 4 :: AC-3 (4)
#    NIST SP 800-53 Revision 4 :: SI-6 a
#
#################################################################
{%- set stig_id = 'RHEL-07-020211' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat1/files' %}
{%- set selConfig = '/etc/selinux/config' %}
{%- set selLink = '/etc/sysconfig/selinux' %}
{%- set selType = 'SELINUXTYPE' %}
{%- set typeMode = 'targeted' %}
{%- set selPolModule = 'selinux-policy-targeted' %}

script_{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stig_id }}.sh
    - cwd: /root

{%- if salt.pkg.version(selPolModule) %}
symlink_{{ stig_id }}-selinxCfg:
  file.symlink:
    - name: {{ selLink }}
    - target: {{ selConfig }}

set_{{ stig_id }}-selType:
  file.replace:
    - name: {{ selConfig }}
    - pattern: '^{{ selType }}=.*$'
    - repl: '{{ selType }}={{ typeMode }}'
    - append_if_not_found: True
{%- else %}
notify_{{ stig_id }}-selWarn:
  cmd.run:
    - name: 'printf "WARNING: STIG-compatible policy-modules not\n  installed. Install before\n  rebooting or system may fail\n  to properly restart."'
{%- endif %}
