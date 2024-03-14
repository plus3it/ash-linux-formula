# Ref Doc:    STIG - RHEL 8 v1r9
# Finding ID: V-230546
# Rule ID:    SV-230546r858824_rule
# STIG ID:    RHEL-08-040282
# SRG ID:     SRG-OS-000480-GPOS-00227
#
# Finding Level: medium
#
# Rule Summary:
#       The OS must restrict usage of ptrace to descendant processes.
#
# References:
#   CCI:
#     - CCI-000366
#   NIST SP 800-53 :: CM-6 b
#   NIST SP 800-53A :: CM-6.1 (iv)
#   NIST SP 800-53 Revision 4 :: CM-6 b
#
###########################################################################
{%- set stig_id = 'RHEL-08-040282' %}
{%- set helperLoc = tpldir ~ '/files' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}
{%- set searchDirs =[
  '/etc/sysctl.d/',
  '/lib/sysctl.d/',
  '/run/sysctl.d',
  '/usr/lib/sysctl.d',
  '/usr/local/lib/sysctl.d',
] %}
{%- set sysctlFiles = [ '/etc/sysctl.conf' ] %}

{{ stig_id }}-description:
  test.show_notification:
    - text: |
        --------------------------------------
        STIG Finding ID: V-230311
             The OS must restrict usage of the
             ptrace utility to descendant
             processes.
        --------------------------------------

{%- if stig_id in skipIt %}
notify_{{ stig_id }}-skipSet:
  cmd.run:
    - name: 'printf "\nchanged=no comment=''Handler for {{ stig_id }} has been selected for skip.''\n"'
    - stateful: True
    - cwd: /root
{%- else %}
  {%- for searchDir in searchDirs %}
    {%- do sysctlFiles.extend(salt.file.find(searchDir, type='f', name='*.conf', grep='kernel\.yama\.ptrace_scope')) %}
  {%- endfor %}
  {%- for sysctlFile in sysctlFiles %}
Fix kernel.yama\.ptrace_scope in {{ sysctlFile }}:
  file.replace:
    - name: '{{ sysctlFile }}'
    - pattern: '^(\s*|#(\s*|))(kernel\.yama\.ptrace_scope)(\s*=\s*).*$'
    - repl: '\g<3>\g<4>1'
  {%- endfor %}
{%- endif %}
