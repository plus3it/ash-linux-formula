# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38656
# Finding ID:	V-38656
# Version:	RHEL-06-000272
# Finding Level:	Low
#
#     The system must use SMB client signing for connecting to samba 
#     servers using smbclient. Packet signing can prevent man-in-the-middle 
#     attacks which modify SMB packets in transit.
#
#  CCI: CCI-000366
#  NIST SP 800-53 :: CM-6 b
#  NIST SP 800-53A :: CM-6.1 (iv)
#  NIST SP 800-53 Revision 4 :: CM-6 b
#
############################################################

{%- set stigId = 'V38656' %}
{%- set helperLoc = 'ash-linux/el6/STIGbyID/cat3/files' %}

script_{{ stigId }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stigId }}.sh
    - cwd: /root

# If the Samba config files are installed...
{%- if salt.pkg.version('samba-common') %}
  # and the "client signing" option is already set to some value,
  # override as necessary
  {%- if salt.file.search('/etc/samba/smb.conf', '^[ 	]*client signing') or salt.file.search('/etc/samba/smb.conf', '^client signing') %}
paramSet_{{ stigId }}-clientSigning:
  file.replace:
    - name: '/etc/samba/smb.conf'
    - pattern: 'client signing[ 	]=.*$'
    - repl: 'client signing = mandatory'
  {%- else %}
  # ...otherwise, set a value (append immediately after [global]
  # stanza's header
paramSet_{{ stigId }}-clientSigning:
  file.replace:
    - name: '/etc/samba/smb.conf'
    - pattern: '^(?P<srctok>^\[global\]$)'
    - repl: '\g<srctok>\n\n# client signing set per STIG-ID V-38656\n\tclient signing = mandatory'
  {%- endif %}
# If the Samba config files are not installed...
{%- else %}
paramSet_{{ stigId }}-clientSigning:
  cmd.run:
    - name: 'echo "No relevant findings: Samba configuration components not installed"'
{%- endif %}
