# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38675
# Finding ID:	V-38675
# Version:	RHEL-06-000308
# Finding Level:	Low
#
#     Process core dumps must be disabled unless needed. A core dump 
#     includes a memory image taken at the time the operating system 
#     terminates an application. The memory image could contain sensitive 
#     data and is generally useful only for developers trying to debug
#     problems.
#
#  CCI: CCI-000366
#  NIST SP 800-53 :: CM-6 b
#  NIST SP 800-53A :: CM-6.1 (iv)
#  NIST SP 800-53 Revision 4 :: CM-6 b
#
############################################################

script_V38675-describe:
  cmd.script:
  - source: salt://STIGbyID/cat3/files/V38675.sh

{% if salt['file.search']('/etc/security/limits.conf','hard[ 	]core') %}
  # Check for already correctly-set value and report
  {% if salt['file.search']('/etc/security/limits.conf','^[ 	]\*[ 	]*hard[ 	]*core[ 	]0') %}
set_V38675-noCores:
  cmd.run:
  - name: 'echo "Core dumps already disabled"'
  {% endif %}
  # Check for commented correct value and uncomment
  {% if salt['file.search']('/etc/security/limits.conf','^#[ 	]*\[ 	]*hard[ 	]core[ 	]*0') %}
set_V38675-noCores:
  file.uncomment:
  - name: '/etc/security/limits.conf'
  - regex: 'hard[ 	]core'
  {% endif %}
  # Check for other value settings and correct
  {% if salt['file.search']('/etc/security/limits.conf','^[ 	]*\[ 	]*hard[ 	]core[ 	].*') %}
set_V38675-noCores:
  file.replace:
  - name: '/etc/security/limits.conf'
  - pattern:
  - repl: '*	hard 	core	0'
  {% endif %}
# Append if no "hard core" value is found
{% else %}
set_V38675-noCores:
  file.append:
  - name: '/etc/security/limits.conf'
  - text: '*	hard 	core	0'
{% endif %}

