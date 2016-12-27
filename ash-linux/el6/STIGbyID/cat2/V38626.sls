# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38626
# Finding ID:	V-38626
# Version:	RHEL-06-000253
# Finding Level:	Medium
#
#     The LDAP client must use a TLS connection using trust certificates 
#     signed by the site CA. The tls_cacertdir or tls_cacertfile directives 
#     are required when tls_checkpeer is configured (which is the default 
#     for openldap versions 2.1 and up). These directives define the path 
#     to the trust ...
#
#  CCI: CCI-000776
#  NIST SP 800-53 :: IA-2 (9)
#  NIST SP 800-53A :: IA-2 (9).1 (ii)
#
############################################################

{%- set stigId = 'V38626' %}
{%- set helperLoc = 'ash-linux/el6/STIGbyID/cat2/files' %}
{%- set ldapCnf = '/etc/pam_ldap.conf' %}

script_{{ stigId }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stigId }}.sh
    - cwd: '/root'

{%- if salt.pkg.version('pam_ldap') and salt.file.search(ldapCnf, '^tls_cacert') %}
file_{{ stigId }}-replCertdir:
  file.replace:
    - name: '{{ ldapCnf }}'
    - pattern: '^tls_cacertdir.*$'
    - repl: 'tls_cacertdir /etc/pki/tls/CA'

file_{{ stigId }}-replCertfile:
  file.replace:
    - name: '{{ ldapCnf }}'
    - pattern: '^tls_cacertfile.*$'
    - repl: 'tls_cacertfile /etc/pki/tls/CA/cacert.pem'

{%- elif salt.pkg.version('pam_ldap') and not salt.file.search(ldapCnf, '^tls_cacert') %}
file_{{ stigId }}-appendCertdir:
  file.append:
    - name: '{{ ldapCnf }}'
    - text: |
        
        # LDAP TLS certificates must come from trusted CA (per STIG V-38626)
        tls_cacertdir /etc/pki/tls/CA

file_{{ stigId }}-appendCertfile:
  file.append:
    - name: '{{ ldapCnf }}'
    - text: |
        
        # LDAP TLS certificates must come from trusted CA (per STIG V-38626)
        tls_cacertfile /etc/pki/tls/CA/cacert.pem

{%- elif not salt.pkg.version('pam_ldap') %}
cmd_{{ stigId }}-notice:
  cmd.run:
    - name: 'echo "LDAP PAM modules not installed"'
{%- endif %}
