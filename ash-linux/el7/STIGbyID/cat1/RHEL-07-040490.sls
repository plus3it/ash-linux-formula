# Finding ID:	RHEL-07-040490
# Version:	RHEL-07-040490_rule
# SRG ID:	SRG-OS-000480-GPOS-00227
# Finding Level:	high
#
# Rule Summary:
#	A File Transfer Protocol (FTP) server package must not be
#	installed unless needed.
#
# CCI-000366
#    NIST SP 800-53 :: CM-6 b
#    NIST SP 800-53A :: CM-6.1 (iv)
#    NIST SP 800-53 Revision 4 :: CM-6 b
#
#################################################################
{%- set stig_id = 'RHEL-07-040490' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat1/files' %}
{%- set ftpds = (
                  'proftpd',
                  'pure-ftpd',
                  'vsftpd'
                ) %}

script_{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stig_id }}.sh
    - cwd: /root

{% if salt['pkg.version'](*ftpds) %}
  {%- for ftpd in ftpds %}
    {%- if salt['pkg.version'](ftpd) %}
cmd_{{ stig_id }}-{{ ftpd }}-notify:
  cmd.run:
    - name: 'echo "Found ftp-server package {{ ftpd }} installed." > /dev/stderr && exit 1'
    - cwd: /root
    {%- endif %}
  {%- endfor %}
{%- endif %}
