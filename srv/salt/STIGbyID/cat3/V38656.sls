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

script_V38656-describe:
  cmd.script:
  - source: salt://STIGbyID/cat3/files/V38656.sh

# If the Samba config files are installed...
{% if salt['pkg.version']('samba-common') %}
  # and the 'client signing' option is already set to some value,
  # override as necessary
  {% if salt['file.search']('/etc/samba/smb.conf', '^[ 	]*client signing') %}
salt['file.search']('/etc/samba/smb.conf', '^client signing') %}
paramSet_V38656-clientSigning:
  file.replace:
  - pattern: 'client signing.*$'
  - repl: 'client signing = mandatory'
  {% else %}
  # ...otherwise, set a value (append immediately after [global]
  # stanza's header
paramSet_V38656-clientSigning:
  file.replace:
  - name: '/etc/samba/smb.conf'
  - pattern: '^(?P<srctok>^\[global\]$)'
  - repl: '\g<srctok>\n\tclient signing = mandatory'
# If the Samba config files are not installed...
{% else %}
paramSet_V38656-clientSigning:
  cmd.run:
  - name: 'echo "No relevant findings: Samba configuration components not installed"'
{% endif %}
