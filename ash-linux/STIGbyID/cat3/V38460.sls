# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38460
# Finding ID:	V-38460
# Version:	RHEL-06-000515
# Finding Level:	Low
#
#     The NFS server must not have the all_squash option enabled. The 
#     "all_squash" option maps all client requests to a single anonymous 
#     uid/gid on the NFS server, negating the ability to track file access 
#     by user ID.
#
#  CCI: CCI-000764
#  NIST SP 800-53 :: IA-2
#  NIST SP 800-53A :: IA-2.1
#  NIST SP 800-53 Revision 4 :: IA-2
#
############################################################

script_V38460-describe:
  cmd.script:
    - source: salt://STIGbyID/cat3/files/V38460.sh

{% if salt['pkg.version']('nfs-utils') %}
  {% if salt['file.search']('/etc/exports', 'all_squash') %}
file_V38460-onlyOpt:
  file.replace:
    - name: '/etc/exports'
    - pattern: '\(all_squash\)'
    - repl: ''

file_V38460-firstOpt:
  file.replace:
    - name: '/etc/exports'
    - pattern: '\(all_squash,'
    - repl: '('

file_V38460-secondaryOpt:
  file.replace:
    - name: '/etc/exports'
    - pattern: ',all_squash'
    - repl: ''
  {% else %}
cmd_V38460-notice:
  cmd.run:
    - name: 'echo "No NFS exports found with all_squash option enabled"'
  {% endif %}
{% else %}
cmd_V38460-notice:
  cmd.run:
    - name: 'echo "NFS service not installed: security control not relevant"'
{% endif %}
