include:
- STIGbyID/cat1/V770
- STIGbyID/cat1/V38476
- STIGbyID/cat1/V38491
- STIGbyID/cat1/V38497
- STIGbyID/cat1/V38587
- STIGbyID/cat1/V38589
- STIGbyID/cat1/V38591
- STIGbyID/cat1/V38594
- STIGbyID/cat1/V38598
- STIGbyID/cat1/V38602
- STIGbyID/cat1/V38607
- STIGbyID/cat1/V38614
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

