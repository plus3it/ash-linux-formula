# Finding ID:	RHEL-07-040030
# Version:	RHEL-07-040030_rule
# SRG ID:	SRG-OS-000066-GPOS-00034
# Finding Level:	medium
# 
# Rule Summary:
#	The operating system, for PKI-based authentication, must
#	validate certificates by performing RFC 5280-compliant
#	certification path validation.
#
# CCI-000185 
#    NIST SP 800-53 :: IA-5 (2) 
#    NIST SP 800-53A :: IA-5 (2).1 
#    NIST SP 800-53 Revision 4 :: IA-5 (2) (a) 
#
#################################################################
{%- set stig_id = 'RHEL-07-040030' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat2/files' %}
{%- set pkgChk = 'pam_pkcs11' %}
{%- set cfgFile = '/etc/pam_pkcs11/pam_pkcs11.conf' %}
{%- set chkParm = 'cert_policy' %}

script_{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stig_id }}.sh
    - cwd: /root

{%- if salt.pkg.version(pkgChk) %}
file_{{ stig_id }}-{{ cfgFile }}:
  file.replace:
    - name: '{{ cfgFile }}'
    - pattern: '{{ chkParm }} = .*$'
    - repl: '{{ chkParm }} = ca, ocsp_on, signature;'
{%- else %}
notify_{{ stig_id }}-notInstalled:
  cmd.run:
    - name: 'printf "\nchanged=no comment=''{{ pkgChk }} packages not installed.''\n"'
    - cwd: /root
    - stateful: True
{%- endif %}
