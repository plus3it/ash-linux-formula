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
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}
{%- set ftpds = (
                  'proftpd',
                  'pure-ftpd',
                  'vsftpd'
                ) %}
{%- set foundFtpds = [] %}

script_{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stig_id }}.sh
    - cwd: /root

{%- if stig_id in skipIt %}
notify_{{ stig_id }}-skipSet:
  cmd.run:
    - name: 'printf "\nchanged=no comment=''Handler for {{ stig_id }} has been selected for skip.''\n"'
    - stateful: True
    - cwd: /root
{%- elif salt.pkg.version(*ftpds) %}
  {%- for ftpd in ftpds %}
    {%- if salt.pkg.version(ftpd) %}
      {%- do foundFtpds.append(ftpd) %}
cmd_{{ stig_id }}-{{ ftpd }}-notify:
  cmd.run:
    - name: 'printf "\nchanged=no comment=''Found ftp-server package {{ ftpd }} installed.''\n" ; /bin/false'
    - cwd: /root
    - stateful: True
    {%- endif %}
  {%- endfor %}
  {%- if not foundFtpds %}
cmd_{{ stig_id }}-noFtpds:
  cmd.run:
    - name: 'printf "\nchanged=no comment=''Found no ftp-server packages installed.''\n"'
    - cwd: /root
    - stateful: True
  {%- endif %}
{%- endif %}
