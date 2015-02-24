# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38517
# Finding ID:	V-38517
# Version:	RHEL-06-000127
# Finding Level:	Medium
#
#     The Transparent Inter-Process Communication (TIPC) protocol must be 
#     disabled unless required. Disabling TIPC protects the system against 
#     exploitation of any flaws in its implementation.
#
#  CCI: CCI-000382
#  NIST 800-53 :: CM-7
#  NIST 800-53A :: CM-7.1 (iii)
#  NIST 800-53 Revision 4 :: CM-7 b
#
############################################################

{%- set stig_id = '38517' %}
{%- set file = '/etc/modprobe.d/tipc.conf' %}

script_V{{ stig_id }}-describe:
  cmd.script:
    - source: salt://ash-linux/STIGbyID/cat2/files/V{{ stig_id }}.sh
    - cwd: '/root'

file-V{{ stig_id }}-touchRules:
  file.touch:
    - name: '{{ file }}'

file_V{{ stig_id }}-appendBlacklist:
  file.append:
    - name: '{{ file }}'
    - text: 'install tipc /bin/false'
    - require:
      - file: file-V{{ stig_id }}-touchRules
    - onlyif:
      - 'test -f {{ file }}'
