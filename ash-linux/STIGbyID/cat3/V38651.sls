# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38651
# Finding ID:	V-38651
# Version:	RHEL-06-000342
# Finding Level:	Low
#
#     The umask value influences the permissions assigned to files when 
#     they are created. A misconfigured umask value could result in files 
#     with excessive permissions that can be read and/or written to by 
#     unauthorized users. 
#
#  CCI: CCI-000366
#  NIST SP 800-53 :: CM-6 b
#  NIST SP 800-53A :: CM-6.1 (iv)
#  NIST SP 800-53 Revision 4 :: CM-6 b
#
############################################################
 
script_V38651-describe:
  cmd.script:
    - source: salt://ash-linux/STIGbyID/cat3/files/V38651.sh
    - cwd: /root

{% if salt['file.search']('/etc/bashrc', '^[   ]*umask[ 	][0-9][0-9]') %}
file_V38651-bashrcUmask:
  file.replace:
    - name: '/etc/bashrc'
    - pattern: 'umask[ 	][0-9][0-9]*'
    - repl: 'umask 077'
{% else %}
file_V38651-bashrcUmask:
  file.append:
    - name: '/etc/bashrc'
    - text:
      - ' '
      - '# Umask must be set to "077" (per STIG V-38651)'
      - 'umask 077'
{% endif %}

# If AT&T KSH is instelled...
{% if salt['pkg.version']('ksh') %}
  {% if salt['file.search']('/etc/kshrc', '^[   ]*umask') %}
file_V38651-kshrcUmask:
  file.replace:
    - name: '/etc/kshrc'
    - pattern: 'umask[ 	][0-9][0-9]*'
    - repl: 'umask 077'
  {% endif %}

  {% if salt['file.search']('/etc/skel/.kshrc', '^[   ]*umask') %}
file_V38651-kshrcUmaskSkel:
  file.replace:
    - name: '/etc/skel/.kshrc'
    - pattern: 'umask[ 	][0-9][0-9]*'
    - repl: 'umask 077'
  {% endif %}
{% endif %}


# If BSD enhanced-KSH is instelled...
{% if salt['pkg.version']('mksh') %}
  {% if salt['file.search']('/etc/mkshrc', '^[   ]*umask') %}
file_V38651-mkshrcUmask:
  file.replace:
    - name: '/etc/mkshrc'
    - pattern: 'umask[ 	][0-9][0-9]*'
    - repl: 'umask 077'
  {% endif %}

  {% if salt['file.search']('/etc/skel/.mkshrc', '^[   ]*umask') %}
file_V38651-mkshrcUmaskSkel:
  file.replace:
    - name: '/etc/skel/.mkshrc'
    - pattern: 'umask[ 	][0-9][0-9]*'
    - repl: 'umask 077'
  {% endif %}
{% endif %}
