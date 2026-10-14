vcl 4.1;

# Example wiring: the WordPress backend and the rendered edge.vcl. The logic lives in edge.vcl.
backend wordpress {
    .host = "wordpress";
    .port = "80";
}

# Rendered from edge.vcl by render-vcl.sh before varnishd starts.
include "/tmp/edge.vcl";
