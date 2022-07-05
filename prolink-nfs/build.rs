fn proces_xdr_file(src_path: &str) {
    println!("cargo:rerun-if-changed={}", src_path);
    xdrgen::compile(src_path).expect("xdrgen simple.x failed");
}

fn main() {
    proces_xdr_file("src/bind.x");
    proces_xdr_file("src/mount.x");
    proces_xdr_file("src/nfs.x");
    proces_xdr_file("src/rpc.x");
}
