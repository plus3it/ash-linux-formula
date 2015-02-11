# STIG URL: http://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2014-06-11/finding/V-38691
# Finding ID:	V-38691
# Version:	RHEL-06-000331
# Finding Level:	Medium
#
#     The Bluetooth service must be disabled. Disabling the "bluetooth" 
#     service prevents the system from attempting connections to Bluetooth 
#     devices, which entails some security risk. Nevertheless, variation in 
#     this risk decision may be expected ...
#
#  CCI: CCI-000085
#  NIST SP 800-53 :: AC-19 c
#  NIST SP 800-53A :: AC-19.1 (iii)
#
############################################################

script_V38691-describe:
  cmd.script:
    - source: salt://ash-linux/STIGbyID/cat2/files/V38691.sh

{% if salt['file.file_exists']('/etc/init.d/bluetooth') %}
# Ensure bluetooth service is disabled and stopped
svc_V38691-bluetoothEnabled:
  service.disabled:
    - name: 'bluetooth'

svc_V38691-bluetoothRunning:
  service.dead:
   - name: 'bluetooth'
{% else %}
notice_V38691-noBTservice:
  cmd.run:
    - name: 'echo "Info: BlueTooth service not present."'
{% endif %}
