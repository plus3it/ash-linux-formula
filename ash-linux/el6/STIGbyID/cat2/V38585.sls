# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38585
# Finding ID:	V-38585
# Version:	RHEL-06-000068
# Finding Level:	Medium
#
#     The system boot loader must require authentication. Password
#     protection on the boot loader configuration ensures users with
#     physical access cannot trivially alter important bootloader settings.
#     These include which kernel to use, and whether to enter ...
#
#  CCI: CCI-000213
#  NIST SP 800-53 :: AC-3
#  NIST SP 800-53A :: AC-3.1
#  NIST SP 800-53 Revision 4 :: AC-3
#
############################################################

{%- set stig_id = 'V38585' %}
{%- set helperLoc = 'ash-linux/el6/STIGbyID/cat2/files' %}
{%- set chkFile = '/boot/grub/grub.conf' %}
{%- set grubPasswd = '$6$THISISNOTAVALIDCRPYTSTRING' %}

script_{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stig_id }}.sh
    - cwd: '/root'

# Check for compliant (SHA512) GRUB password - alert if not set
{%- if salt.file.search(chkFile, '^password --encrypted \$6', ignore_if_missing=True) %}

notify_{{ stig_id }}-wontFix:
  cmd.run:
    - name: 'echo "GRUB password already set using valid encryption-algorithm"'

{%- else %}

  # If this is an Amazon HVM, we can feel free to set a GRUB password
  #   (no console means won't matter if the value is valid
  #   or overridden)
  {%- if salt.grains.get('productname') == 'HVM domU' %}

insert_{{ stig_id }}-grubPasswd:
  file.replace:
    - name: '{{ chkFile }}'
    - pattern: '^(?P<srctok>timeout=.*)'
    - repl: '\g<srctok>\npassword --encrypted {{ grubPasswd }}'

  {%- else %}

notify_{{ stig_id }}-wontFix:
  cmd.run:
    - name: 'printf "
*****************************************************\n
* GRUB not password-protected with SHA512-encrypted\n
*      password: MANUAL REMEDIATION REQUIRED\n
*****************************************************\n"'

  {%- endif %}
{%- endif %}
