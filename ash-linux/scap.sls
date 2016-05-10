{%- set ver = grains['osmajorrelease'] %}
include:
  - ash-linux.stig
  - ash-linux.el{{ ver }}.SCAPonly
