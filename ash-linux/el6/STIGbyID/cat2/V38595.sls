# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38595
# Finding ID:	V-38595
# Version:	RHEL-06-000349
# Finding Level:	Medium
#
#     The system must be configured to require the use of a CAC, PIV 
#     compliant hardware token, or Alternate Logon Token (ALT) for 
#     authentication. Smart card login provides two-factor authentication 
#     stronger than that provided by a username/password combination. Smart 
#     cards leverage a PKI (public key infrastructure) in order to provide 
#     and ...
#
#  CCI: CCI-000765
#  NIST SP 800-53 :: IA-2 (1)
#  NIST SP 800-53A :: IA-2 (1).1
#  NIST SP 800-53 Revision 4 :: IA-2 (1)
#
############################################################

{%- set stigId = 'V38595' %}
{%- set helperLoc = 'ash-linux/el6/STIGbyID/cat2/files' %}

script_{{ stigId }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stigId }}.sh
    - cwd: '/root'

cmd_{{ stigId }}-notice:
  cmd.run:
    - name: 'echo "Not a technical/enforcible control"'
