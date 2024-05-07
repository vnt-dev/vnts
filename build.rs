use static_files::resource_dir;
fn main() -> std::io::Result<()> {
    std::fs::create_dir_all("src/proto").unwrap();
    protobuf_codegen::Codegen::new()
        .pure()
        .out_dir("src/proto")
        .inputs(["proto/message.proto"])
        .include("proto")
        .run()
        .expect("Codegen failed.");

    resource_dir("./static").build()
}
