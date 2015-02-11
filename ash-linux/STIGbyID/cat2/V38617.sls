# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38617
# Finding ID:	V-38617
# Version:	RHEL-06-000243
# Finding Level:	Medium
#
#     The SSH daemon must be configured to use only FIPS 140-2 approved 
#     ciphers. Approved algorithms should impart some level of confidence 
#     in their implementation. These are also required for compliance.
#
#  CCI: CCI-001144
#  NIST SP 800-53 :: SC-13
#  NIST SP 800-53A :: SC-13.1
#
############################################################

script_V38617-describe:
  cmd.script:
    - source: salt://ash-linux/STIGbyID/cat2/files/V38617.sh

{% if salt['file.search']('/etc/ssh/sshd_config', '^Ciphers')
 %}
file_V38617-repl:
  file.replace:
    - name: '/etc/ssh/sshd_config'
    - pattern: '^Ciphers.*$'
    - repl: 'Ciphers aes128-ctr,aes192-ctr,aes256-ctr,aes128-cbc,3des-cbc,aes192-cbc,aes256-cbc'
{% else %}
file_V38617-append:
  file.append:
    - name: '/etc/ssh/sshd_config'
    - text:
      - ' '
      - '# SSH service must allow only FIPS 140-2 ciphers (per STIG V-38617)'
      - 'Ciphers aes128-ctr,aes192-ctr,aes256-ctr,aes128-cbc,3des-cbc,aes192-cbc,aes256-cbc'
{% endif %}

