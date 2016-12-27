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

{%- set stigId = 'V38702' %}
{%- set helperLoc = 'ash-linux/el6/STIGbyID/cat3/files' %}

script_{{ stigId }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stigId }}.sh
    - cwd: /root

# Check to see if vsftpd service is installed
{%- if salt.pkg.version('vsftpd') %}
  {%- set vsftpdConf = '/etc/vsftpd/vsftpd.conf' %}
  {%- set logEnable = 'xferlog_enable' %}
  {%- set logFormat = 'xferlog_std_format' %}
  {%- set logVerbosity = 'log_ftp_protocol' %}

  # ...and see if transfer-logging is already enabled
  {%- if salt.file.search(vsftpdConf, '^' + logEnable + '=YES') %}
file_{{ stigId }}-xferLog:
  cmd.run:
    - name: 'echo "The {{ logEnable }} option is already appropriately set"'

  # ...set it to enabled if already explicitly disabled
  {%- elif salt.file.search(vsftpdConf, '^' + logEnable + '=NO') %}
file_{{ stigId }}-xferLog:
  file.replace:
    - name: {{ vsftpdConf }}
    - pattern: '^{{ logEnable }}.*$'
    - repl: '{{ logEnable }}=YES'

  # ...if not defined at all
  {%- else  %}
file_{{ stigId }}-xferLog:
  file.append:
    - name: {{ vsftpdConf }}
    - text: |
        
        # Enable transfer-logging (per STIG V-38702)
        {{ logEnable }}=YES
  {%- endif %}

  # ...and see if standard-logging is explicitly disabled
  {%- if salt.file.search(vsftpdConf, '^' + logFormat + '=NO') %}
file_{{ stigId }}-logFmt:
  cmd.run:
    - name: 'echo "The {{ logFormat }} option is already appropriately set"'

  # ...set it to disabled if already explicitly enabled
  {%- elif salt.file.search(vsftpdConf, '^' + logFormat + '=YES') %}
file_{{ stigId }}-logFmt:
  file.replace:
    - name: {{ vsftpdConf }}
    - pattern: '^{{ logFormat }}.*$'
    - repl: '{{ logFormat }}=NO'

  # ...if not defined at all
  {%- else  %}
file_{{ stigId }}-logFmt:
  file.append:
    - name: {{ vsftpdConf }}
    - text: |
        
        # Enable verbose logging (per STIG V-38702)
        {{ logFormat }}=YES
  {%- endif %}

  # ...and see if verbose-logging is already enabled
  {%- if salt.file.search(vsftpdConf, '^' + logVerbosity + '=YES') %}
file_{{ stigId }}-logVerbose:
  cmd.run:
    - name: 'echo "The {{ logVerbosity }} option is already appropriately set"'

  # ...set it to enabled if already explicitly disabled
  {%- elif salt.file.search(vsftpdConf, '^' + logVerbosity + '=NO') %}
file_{{ stigId }}-logVerbose:
  file.replace:
    - name: {{ vsftpdConf }}
    - pattern: '^{{ logVerbosity }}.*$'
    - repl: '{{ logVerbosity }}=YES'

  # ...if not defined at all
  {%- else  %}
file_{{ stigId }}-logVerbose:
  file.append:
    - name: {{ vsftpdConf }}
    - text: |
        
        # Enable transfer-logging (per STIG V-38702)
        {{ logVerbosity }}=YES
  {%- endif %}

# If not installed, call out as much...
{%- else  %}
file_{{ stigId }}-modify:
  cmd.run:
    - name: 'echo "FTP (vsftpd} service not installed"'
{%- endif %}
