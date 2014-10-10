include:
- STIGbyID/cat1/V38668
- STIGbyID/cat1/V38677
- STIGbyID/cat1/V38701


# (Following are being re-worked and are commented out, for now)
## file_GEN001400_shadow:
##   file.managed:
##   - name: /etc/shadow
##   - user: root
##   - group: root
##   - mode: 0000
## 
## file_GEN001400_passwd:
##   file.managed:
##   - name: /etc/passwd
##   - user: root
##   - group: root
##   - mode: 0644
## 
## script_GEN001640:
##   cmd.script:
##   - source: salt://STIGbyID/cat1/files/gen001640.sh
## 
## script_V38497:
##   cmd.script:
##   - source: salt://STIGbyID/cat1/files/V38497.sh
## 
