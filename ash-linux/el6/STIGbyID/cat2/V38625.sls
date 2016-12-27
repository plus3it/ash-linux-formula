# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38625
# Finding ID:	V-38625
# Version:	RHEL-06-000252
# Finding Level:	Medium
#
#     If the system is using LDAP for authentication or account 
#     information, the system must use a TLS connection using FIPS 140-2 
#     approved cryptographic algorithms. The ssl directive specifies 
#     whether to use ssl or not. If not specified it will default to "no". 
#     It should be set to "start_tls" rather than doing LDAP over SSL.
#
#  CCI: CCI-001453
#  NIST SP 800-53 :: AC-17 (2)
#  NIST SP 800-53A :: AC-17 (2).1
#  NIST SP 800-53 Revision 4 :: AC-17 (2)
#
############################################################

{%- set stigId = 'V38625' %}
{%- set helperLoc = 'ash-linux/el6/STIGbyID/cat2/files' %}
{%- set ldapCnf = '/etc/pam_ldap.conf' %}

script_{{ stigId }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stigId }}.sh
    - cwd: '/root'

{%- if salt.pkg.version('pam_ldap') and salt.file.search(ldapCnf, '^ssl') %}
file_{{ stigId }}-repl:
  file.replace:
    - name: '{{ ldapCnf }}'
    - pattern: '^ssl.*$'
    - repl: 'ssl start_tls'
{%- elif salt.pkg.version('pam_ldap') and not salt.file.search(ldapCnf, '^ssl') %}
file_{{ stigId }}-append:
  file.append:
    - name: '{{ ldapCnf }}'
    - text:
      - ' '
      - '# LDAP auth-queries must use TLS (per STIG V-38625)'
      - 'ssl start_tls'
{%- elif not salt.pkg.version('pam_ldap') %}
cmd_{{ stigId }}-notice:
  cmd.run:
    - name: 'echo "LDAP PAM modules not installed"'
{%- endif %}
