# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38438
# Finding ID:	V-38438
# Version:	RHEL-06-000525
# Finding Level:	Low
#
#     Each process on the system carries an "auditable" flag which 
#     indicates whether its activities can be audited. Although "auditd" 
#     takes care of enabling this for all processes which launch after it 
#     does, adding the kernel argument ensures it is set for every process 
#     during boot. 
#
#  CCI: CCI-000169
#  NIST SP 800-53 :: AU-12 a
#  NIST SP 800-53A :: AU-12.1 (ii)
#  NIST SP 800-53 Revision 4 :: AU-12 a
#
############################################################

{%- set stig_id = '38438' %}

script_V{{ stig_id }}-describe:
  cmd.script:
    - source: salt://ash-linux/STIGbyID/cat3/files/V{{ stig_id }}.sh
    - cwd: '/root'

# Enable audit at kernel load
{% if salt['file.search']('/boot/grub/grub.conf', 'kernel') and not salt['file.search']('/boot/grub/grub.conf', 'kernel.*audit=1') %}

file_V{{ stig_id }}-repl:
  file.replace:
    - name: '/boot/grub/grub.conf'
    - pattern: '(?P<srctok>kernel.*$)'
    - repl: '\g<srctok> audit=1'

{% else %}

status_V{{ stig_id }}:
  cmd.run:
    - name: 'echo "Auditing already enabled at boot"'

{% endif %}
