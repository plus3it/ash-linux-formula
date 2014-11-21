# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38702
# Finding ID:	V-38702
# Version:	RHEL-06-000339
# Finding Level:	Low
#
#     The FTP daemon must be configured for logging or verbose mode. To 
#     trace malicious activity facilitated by the FTP service, it must be 
#     configured to ensure that all commands sent to the ftp server are 
#     logged using the verbose vsftpd log format. The default vsftpd log
#     file is /var/log/vsftpd.log
#
#  CCI: CCI-000130
#  NIST SP 800-53 :: AU-3
#  NIST SP 800-53A :: AU-3.1
#  NIST SP 800-53 Revision 4 :: AU-3
#
############################################################

script_V38702-describe:
  cmd.script:
  - source: salt://STIGbyID/cat3/files/V38702.sh

# Check to see if vsftpd service is installed
{% if salt['pkg.version']('vsftpd') %}
  {% set vsftpdConf = '/etc/vsftpd/vsftpd.conf' %}
  {% set parmName = 'xferlog_enable' %}

  # ...and see if xferlog is already enabled
  {% if salt['file.search'](vsftpdConf, '^' + parmName + '=YES') %}
file_V38702-modify:
  cmd.run:
  - name: 'echo "The {{ parmName }} option is already appropriately set"'

  # ...set it to enabled if already explicitly disabled
  {% elif salt['file.search'](vsftpdConf, '^' + parmName + '=NO') %}
file_V38702-modify:
  file.replace:
  - name: {{ vsftpdConf }}
  - pattern: '^{{ parmName }}.*$'
  - repl: '{{ parmName }}=YES'

  # ...if not defined at all
  {% else  %}
file_V38702-modify:
  file.append:
  - name: {{ vsftpdConf }}
  - text:
    - ' '
    - '# Enable standard security banners (per STIG V-38702)'
    - '{{ parmName }}=YES'
  {% endif %}

# If not installed, call out as much...
{% else  %}
file_V38702-modify:
  cmd.run:
  - name: 'echo "FTP (vsftpd} service not installed"'
{% endif %}
