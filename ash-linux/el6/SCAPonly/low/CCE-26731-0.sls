# This Salt test/lockdown implements a SCAP item that has not yet been
# merged into the DISA-published STIGS
#
# Rule ID:
# - rpm_verify_permissions
#
# Security identifiers:
# - CCE-26731-0
#
# Rule Summary: Use RPM tools to verify correct file permissions
#
# Rule Text: Permissions on system binaries and configuration files that 
#            are too generous could allow an unauthorized user to gain 
#            privileges that they should not have. The permissions set 
#            by the vendor should be maintained. Any deviations from 
#            this baseline should be investigated. The RPM package 
#            management system can check file access permissions of 
#            installed software packages, including many that are 
#            important to system security. 
#
#################################################################

{%- set helperLoc = 'ash-linux/el6/SCAPonly/low/files' %}
{%- set scapId = 'CCE-26731-0' %}

script_{{ scapId }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ scapId }}.sh
    - cwd: '/root'

# Check (and fix as necessary) RPM-owned file permissions
fix_{{ scapId }}-perms:
  cmd.script:
    - source: salt://{{ helperLoc }}/CCE-26731-0_helper.sh
    - cwd: '/root'

