# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38515
# Finding ID:	V-38515
# Version:	RHEL-06-000125
# Finding Level:	Medium
#
#     The Stream Control Transmission Protocol (SCTP) must be disabled 
#     unless required. Disabling SCTP protects the system against 
#     exploitation of any flaws in its implementation.
#
#  CCI: CCI-000382
#  NIST SP 800-53 :: CM-7
#  NIST SP 800-53A :: CM-7.1 (iii)
#  NIST SP 800-53 Revision 4 :: CM-7 b
#
############################################################

{%- set stig_id = '38515' %}
{%- set file = '/etc/modprobe.d/sctp.conf' %}

script_V{{ stig_id }}-describe:
  cmd.script:
    - source: salt://ash-linux/STIGbyID/cat2/files/V{{ stig_id }}.sh

file-V{{ stig_id }}-touchRules:
  file.touch:
    - name: '{{ file }}'

file_V{{ stig_id }}-appendBlacklist:
  file.append:
    - name: '{{ file }}'
    - text: 'install sctp /bin/false'
    - require:
      - file: file-V{{ stig_id }}-touchRules
    - onlyif:
      - 'test -f {{ file }}'
