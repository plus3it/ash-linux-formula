# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38462
# Finding ID:	V-38462
# Version:	RHEL-06-000514
#
#      Ensuring all packages' cryptographic signatures are valid prior
#      to installation ensures the provenance of the software and
#      protects against malicious tampering. 
#
###########################################################################

script_V38462-describe:
  cmd.script:
  - source: salt://STIGbyID/cat1/files/V38462.sh
  - cwd: /root

{% set fileList = [
	'/etc/rpmrc',
	'/usr/lib/rpm/rpmrc',
	'/usr/lib/rpm/redhat/rpmrc',
	'/root/.rpmrc',
] %}
{% for checkFile in fileList %}
{% if salt['file.file_exists'](checkFile) %}
  {% if salt['file.search'](checkFile,'^nosignature') %}
notify_V38462-{{ checkFile }}:
  cmd.run:
  - name: 'echo "WARNING: ''nosignature'' option set in ''{{ checkFile }}''. Fixing." ; exit 1'

comment_V38462-{{ checkFile }}:
  file.comment:
  - name: '{{ checkFile }}'
  - regex: 'nosignature'
  {% else %}
notify_V38462-{{ checkFile }}:
  cmd.run:
  - name: 'echo "Info: ''nosignature'' option not set in ''{{ checkFile }}''"'
  {% endif %}
{% else %}
notify_V38462-{{ checkFile }}:
  cmd.run:
  - name: 'echo "Info: Configuration-file ''{{ checkFile }}'' does not exist"'
{% endif %}
{% endfor %}

