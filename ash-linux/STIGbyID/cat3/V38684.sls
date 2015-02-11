# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38684
# Finding ID:	V-38684
# Version:	RHEL-06-000319
# Finding Level:	Low
#
#     The system must limit users to 10 simultaneous system logins, or a 
#     site-defined number, in accordance with operational requirements. 
#     Limiting simultaneous user logins can insulate the system from denial 
#     of service problems caused by excessive logins. Automated login 
#     processes operating improperly or maliciously may result in an 
#     exceptional number of simultaneous login sessions.
#
#  CCI: CCI-000054
#  NIST SP 800-53 :: AC-10
#  NIST SP 800-53A :: AC-10.1 (ii)
#  NIST SP 800-53 Revision 4 :: AC-10
#
############################################################

script_V38684-describe:
  cmd.script:
    - source: salt://ash-linux/STIGbyID/cat3/files/V38684.sh

{% if salt['file.search']('/etc/security/limits.conf','hard[ 	]*maxlogins') %}

  # Only report if proper setting already present
  {% if salt['file.search']('/etc/security/limits.conf', '^\*[ 	]hard[ 	]*maxlogins[ 	]*10$') %}
set_V38684-noCores:
  cmd.run:
    - name: 'echo "Users already limited to 10 interactive logins"'

  # If proper value present but commented out, uncomment
  {% elif salt['file.search']('/etc/security/limits.conf', '^#\*[ 	]hard[ 	]*maxlogins[ 	]*10$') %}
set_V38684-noCores:
  file.uncomment:
    - name: '/etc/security/limits.conf'
    - regex: '^\*[ 	]hard[ 	]*maxlogins[ 	]*.*$'
    - text: '*	hard 	maxlogins	10'

  # If bad value present, change it
  {% else %}
set_V38684-noCores:
  file.replace:
    - name: '/etc/security/limits.conf'
    - pattern: '^\*[ 	]hard[ 	]*maxlogins[ 	]*.*$'
    - repl: '*	hard 	maxlogins	10'
  {% endif %}

# Append if no "hard maxlogins" value is found
{% else %}
set_V38684-noCores:
  file.append:
    - name: '/etc/security/limits.conf'
    - text: '*	hard	maxlogins	10'
{% endif %}
