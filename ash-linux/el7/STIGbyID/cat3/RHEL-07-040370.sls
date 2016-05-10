# STIG URL:
# Finding ID:	RHEL-07-040370
# Version:	RHEL-07-040370_rule
# SRG ID:	
# Finding Level:	low
#
# Rule Summary:
#     The system must not process IPv4 Internet Control Message 
#     Protocol (ICMP) timestamp requests.
#
# CCI-000366
#    NIST SP 800-53 :: CM-6 b
#    NIST SP 800-53A :: CM-6.1 (iv)
#    NIST SP 800-53 Revision 4 :: CM-6 b
#
#################################################################
{%- set stig_id = 'RHEL-07-040370' %}
{%- set helperLoc = 'ash-linux/el7/STIGbyID/cat3/files' %}
{%- set chkPkg = 'firewalld' %}
{%- set tsRep = 'timestamp-reply' %}
{%- set tsReq = 'timestamp-request' %}

script_{{ stig_id }}-describe:
  cmd.script:
    - source: salt://{{ helperLoc }}/{{ stig_id }}.sh
    - cwd: /root

pkg_{{ stig_id }}-{{ chkPkg }}:
  pkg.installed:
    - name: '{{ chkPkg }}'

svc_{{ stig_id }}-{{ chkPkg }}:
  service.enabled:
    - name: '{{ chkPkg }}'
    - requires: pkg.pkg_{{ stig_id }}-{{ chkPkg }}

# Note: Probably want this state to watch the file.* states. 
# However, currently getting 'Unable to trigger watch for service.enabled'
# errors when the watch-condition is triggered.
##     - watch:
##       - file: file_{{ stig_id }}-{{ tsRep }}
##       - file: file_{{ stig_id }}-{{ tsReq }}

svc_{{ stig_id }}-{{ chkPkg }}-run:
  service.running:
    - name: '{{ chkPkg }}'
    - requires: service.svc_{{ stig_id }}-{{ chkPkg }}

file_{{ stig_id }}-{{ tsRep }}:
  file.managed:
    - name: '/etc/firewalld/icmptypes/{{ tsRep }}.xml'
    - source: salt://{{ helperLoc }}/{{ stig_id }}_{{ tsRep }}.xml
    - user: 'root'
    - group: 'root'
    - makedirs: 'True'
    - dir_mode: '0700'
    - mode: '0400'
    - requires: pkg.pkg_{{ stig_id }}-{{ chkPkg }}

file_{{ stig_id }}-{{ tsReq }}:
  file.managed:
    - name: '/etc/firewalld/icmptypes/{{ tsReq }}.xml'
    - source: salt://{{ helperLoc }}/{{ stig_id }}_{{ tsReq }}.xml
    - user: 'root'
    - group: 'root'
    - makedirs: 'True'
    - dir_mode: '0700'
    - mode: '0400'
    - requires: pkg.pkg_{{ stig_id }}-{{ chkPkg }}

firewalld_{{ stig_id }}-icmp_blocks-public:
  firewalld.present:
    - name: public
    - block_icmp:
      - '{{ tsRep }}'
      - '{{ tsReq }}'
    - default: False
    - masquerade: False
    - ports:
      - 22/tcp
