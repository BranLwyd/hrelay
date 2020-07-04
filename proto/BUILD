load("@rules_proto//proto:defs.bzl", "proto_library")
load("@io_bazel_rules_go//proto:def.bzl", "go_proto_library")

##
## hrelayd messages
##
proto_library(
    name = "hrelayd_proto",
    srcs = ["hrelayd.proto"],
)

go_proto_library(
    name = "hrelayd_go_proto",
    importpath = "github.com/BranLwyd/hrelay/proto/hrelayd_go_proto",
    proto = ":hrelayd_proto",
    visibility = ["//:__subpackages__"],
)

##
## hrelay protocol messages
##
proto_library(
    name = "hrelay_proto",
    srcs = ["hrelay.proto"],
)

go_proto_library(
    name = "hrelay_go_proto",
    importpath = "github.com/BranLwyd/hrelay/proto/hrelay_go_proto",
    proto = ":hrelay_proto",
    visibility = ["//:__subpackages__"],
)
