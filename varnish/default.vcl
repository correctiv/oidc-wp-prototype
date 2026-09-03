vcl 4.1;

# Docker wiring: backends and the rendered secrets. The actual logic lives in edge.vcl.
backend wordpress {
    .host = "wordpress";
    .port = "80";
}

backend auth {
    .host = "auth";
    .port = "3000";
}

include "/etc/varnish/edge.vcl";
include "/etc/varnish/config.vcl";
