const std = @import("std");
const main_impl = @import("main.zig");

// Provide a stub main so std.start can type-check, but rename it to avoid
// clashing with the ObjC main symbol.
pub fn main() callconv(.c) void {}

comptime {
    @export(&main, .{ .name = "__zig_stub_main" });
}

pub export fn lightpanda_start() void {
    const argv0: [:0]const u8 = "LightpandaTV";
    var argv_buf: [1][*:0]u8 = .{ @constCast(argv0.ptr) };
    const env_buf: [0][*:0]u8 = .{};

    std.os.argv = argv_buf[0..];
    std.os.environ = env_buf[0..];

    _ = main_impl.main() catch |err| {
        std.debug.print("lightpanda error: {any}\n", .{err});
    };
}
