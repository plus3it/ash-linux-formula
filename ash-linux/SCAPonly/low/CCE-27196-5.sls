# This Salt test/lockdown implements a SCAP item that has not yet been
# merged into the DISA-published STIGS
#
# Rule ID:
# - rpm_verify_permissions
#
# Security identifiers:
# - CCE-26731-0
#
# Rule Summary: Add noexec Option to Removable Media Partitions
#
# Rule Text: The noexec mount option prevents the direct execution of 
#            binaries on the mounted filesystem. Preventing the direct 
#            execution of binaries from removable media (such as a USB 
#            key) provides a defense against malicious software that may 
#            be present on such untrusted media. Add the noexec option 
#            to the fourth column of /etc/fstab for the line which 
#            controls mounting of any removable media partitions.
#
#            Allowing users to execute binaries from removable media 
#            such as USB keys exposes the system to potential compromise.
#
#################################################################

{%- set helperLoc = 'ash-linux/SCAPonly/low/files' %}
{%- set scapId = 'CCE-26731-0' %}
{%- set parmName = 'net.ipv6.conf.default.accept_ra' %}
{%- set notify_change = 'In-memory configuration of ''{{ parmName }}'' not disab
led' %}
{%- set notify_nochange = '''{{ parmName }}'' already disabled' %}

script_{{ scapId }}-describe:
  cmd.run:
    - name: 'printf "
*************************************************\n
* NOTE: This SCAP-ID already covered by handler *\n
*       for STIG-ID V-38655                     *\n
*************************************************\n"'

