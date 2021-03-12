# Finding ID:	RHEL-07-040040
# Version:	RHEL-07-040040_rule
# SRG ID:	SRG-OS-000067-GPOS-00035
# Finding Level:	medium
#
# Rule Summary:
#	The operating system, for PKI-based authentication, must
#	enforce authorized access to all PKI private keys stored or
#	used by the operating system.
#
# CCI-000186
#    NIST SP 800-53 :: IA-5 (2)
#    NIST SP 800-53A :: IA-5 (2).1
#    NIST SP 800-53 Revision 4 :: IA-5 (2)
#
#################################################################
{%- set stig_id = 'RHEL-07-040040' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat2/files' %}
{%- set skipIt = salt.pillar.get('ash-linux:lookup:skip-stigs', []) %}
{%- set pkgChk = 'pam_pkcs11' %}
{%- set cfgFile = '/etc/pam_pkcs11/pam_pkcs11.conf' %}
{%- set chkParm = 'use_pkcs11_module' %}

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
{%- else %}
  {%- if salt.pkg.version(pkgChk) %}
file_{{ stig_id }}-{{ cfgFile }}:
  file.replace:
    - name: '{{ cfgFile }}'
    - pattern: '{{ chkParm }} = .*$'
    - repl: '{{ chkParm }} = cackey;'
  {%- else %}
notify_{{ stig_id }}-notInstalled:
  cmd.run:
    - name: 'printf "\nchanged=no comment=''{{ pkgChk }} packages not installed.''\n"'
    - cwd: /root
    - stateful: True
  {%- endif %}
{%- endif %}
