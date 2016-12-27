# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-51391
# Finding ID:	V-51391
# Version:	RHEL-06-000018
# Finding Level:	Medium
#
#     A file integrity baseline must be created. For AIDE to be effective,
#     an initial database of "known-good" information about files must be
#     captured and it should be able to be verified against the installed
#     files.
#
#  CCI: CCI-000366
#  NIST SP 800-53 :: CM-6 b
#  NIST SP 800-53A :: CM-6.1 (iv)
#  NIST SP 800-53 Revision 4 :: CM-6 b
#
############################################################

{%- set stigId = 'V51391' %}
{%- set helperLoc = 'ash-linux/el6/STIGbyID/cat2/files' %}

script_{{ stigId }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stigId }}.sh
    - cwd: '/root'

# See if AIDE package is installed
{%- if salt.pkg.version('aide') %}
  # Extract DB directory-path from AIDE config file
  {%- set aideDbDir = salt['cmd.shell']('grep "define DBDIR" /etc/aide.conf | cut -d" " -f 3') %}
  {%- if aideDbDir %}
    # Extract DB file name from AIDE config file
    {%- set aideDbFile = salt['cmd.shell']('grep -e "^database=.*/" /etc/aide.conf | cut -d "/" -f 2') %}
    # Assemble DB file-path from prior
    {%- set aideDbPath = aideDbDir + '/' + aideDbFile %}

    # Check if DB file-path exists
    {%- if salt.file.file_exists(aideDbPath) %}
notify_{{ stigId }}-foundfile:
  cmd.run:
    - name: 'echo "The configured AIDE database [{{ aideDbPath }}] exists" && exit 0'

    # Alert if DB file-path does not exist
    {%- else %}
notify_{{ stigId }}-foundfile:
  cmd.run:
    - name: 'printf "WARNING: The configured AIDE database [{{ aideDbPath }}] does not exist!\n** Run ''/usr/sbin/aide --init'' to create.\n"'
    {%- endif %}
  {%- else %}
notify_{{ stigId }}-foundfile:
  cmd.run:
    - name: 'echo "WARNING: The AIDE database location-definition does not meet test-assumptions. Automated test not possible"'
  {%- endif %}

# Alert if AIDE not installed
{%- else %}
warn_{{ stigId }}-noAide:
  cmd.run:
    - name: 'echo "WARN: The AIDE tools are not installed"'
{%- endif %}
