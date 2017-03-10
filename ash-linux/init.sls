{%- if grains['osmajorrelease'] == '7' %}
include:
  - ash-linux.el7
{%- elif grains['osmajorrelease'] == '6' %}
include:
  - ash-linux.stig
  - ash-linux.scap
  - ash-linux.iavm
{%- endif %}
