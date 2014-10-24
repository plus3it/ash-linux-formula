# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38599
# Finding ID:	V-38599
# Version:	RHEL-06-000348
# Finding Level:	Medium
#
#     The FTPS/FTP service on the system must be configured with the 
#     Department of Defense (DoD) login banner. This setting will cause the 
#     system greeting banner to be used for FTP connections as well.
#
#     Support for vsftpd, gridftpd, proftpd and pure-ftpd
#
############################################################

script_V38599-describe:
  cmd.script:
  - source: salt://STIGbyID/cat2/files/V38599.sh

{% if salt['pkg.version']('nordugrid-arc-gridftpd') %}
cmd_V38599-NotImplemented:
  cmd.run:
  - name: 'echo "NOT YET IMPLEMENTED"'
{% endif %}

###################################
# Banners for the proftpd service
###################################
{% if salt['pkg.version']('proftpd') and salt['file.search']('/etc/proftpd.conf', '^DisplayConnect') %}
file_V38599-repl:
  file.replace:
  - name: '/etc/proftpd.conf'
  - pattern: '^DisplayConnect.*$'
  - repl: 'DisplayConnect	/etc/issue'
{% elif salt['pkg.version']('proftpd') and not salt['file.search']('/etc/proftpd.conf', '^DisplayConnect') %}
file_V38599-repl:
  file.replace:
  - name: '/etc/proftpd.conf'
  - pattern: '^(?P<srctok>ServerIdent.*$)'
  - repl: '\g<srctok>\nDisplayConnect\t\t\t/etc/issue'
{% endif %}
###################################

#####################################
# Banners for the pure-ftpd service
#####################################
{% if salt['pkg.version']('pure-ftpd') and salt['file.search']('/etc/pure-ftpd/pure-ftpd.conf', '^FortunesFile') %}
file_V38599-repl:
  file.replace:
  - name: '/etc/pure-ftpd/pure-ftpd.conf'
  - pattern: '^FortunesFile.*$'
  - repl: 'FortunesFile	/etc/issue'
{% elif salt['pkg.version']('pure-ftpd') and not salt['file.search']('/etc/pure-ftpd/pure-ftpd.conf', '^FortunesFile') %}
file_V38599-append:
  file.append:
  - name: '/etc/pure-ftpd/pure-ftpd.conf'
  - text:
    - ' '
    - '# Enable standard security banners (per STIG V-38599)'
    - 'FortunesFile	/etc/issue'
{% endif %}
#####################################


##################################
# Banners for the vsftpd service
##################################
{% if salt['pkg.version']('vsftpd') and salt['file.search']('/etc/vsftpd/vsftpd.conf', '^banner_file') %}
file_V38599-repl:
  file.replace:
  - name: '/etc/vsftpd/vsftpd.conf'
  - pattern: '^banner_file.*$'
  - repl: 'banner_file=/etc/issue'
{% elif salt['pkg.version']('vsftpd') and not salt['file.search']('/etc/vsftpd/vsftpd.conf', '^banner_file') %}
file_V38599-append:
  file.append:
  - name: '/etc/vsftpd/vsftpd.conf'
  - text:
    - ' '
    - '# Enable standard security banners (per STIG V-38599)'
    - 'banner_file=/etc/issue'
{% endif %}
##################################
