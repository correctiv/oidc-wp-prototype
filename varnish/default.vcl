vcl 4.1;

# Docker wiring: the WordPress backend. The logic lives in edge.vcl.
backend wordpress {
    .host = "wordpress";
    .port = "80";
}

# edge.vcl is rendered from the template at container start (see docker-compose.yml).
include "/tmp/edge.vcl";
