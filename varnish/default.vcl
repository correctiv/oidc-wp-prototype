vcl 4.1;

# Docker wiring: the WordPress backend. The logic lives in edge.vcl.
backend wordpress {
    .host = "wordpress";
    .port = "80";
}

include "/etc/varnish/edge.vcl";
