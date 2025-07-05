extern crate pkg_config;

use bindgen::Formatter;
// use sha2::{Digest, Sha256};
// use std::env;
// use std::fs;
// use std::fs::File;
// use std::io::Read;
// use std::path::{Path, PathBuf};
// use std::process::Command;

fn exists(path: &str) -> bool {
    std::path::Path::new(path).exists()
}

// fn sha256(file_path: &str) -> String {
//     let path = Path::new(file_path);
//     let mut file = File::open(path)
//         .expect(format!("Unable to open the {} file.", file_path).as_str());
//     let mut content = Vec::new();
//     file.read_to_end(&mut content)
//         .expect(format!("Unable to read the {} file.", file_path).as_str());
//     let mut hasher = Sha256::new();
//     hasher.update(&content);
//     format!("{:x}", hasher.finalize())
// }
//
// fn changed() -> bool {
//     let hash = sha256("/usr/local/include/rte_config.h");
//     let date = fs::metadata(Path::new("/usr/local/include/rte_config.h"))
//         .expect("Unable to get metadata of the rte_config.h file. Please check your permissions.")
//         .modified()
//         .expect("Unable to get modified time of the rte_config.h file. Please check your permissions.");
//     let cache_hash = fs::read_to_string(Path::new("archive/.hash"))
//         .expect("Unable to read .hash file under archive directory. Please check your permissions.");
//     let cache_date = fs::read_to_string(Path::new("archive/.date"))
//         .expect("Unable to read .hash file under archive directory. Please check your permissions.");
//     if hash != cache_hash || format!("{:?}", date) != cache_date {
//         true
//     } else {
//         false
//     }
// }

// fn create_dpdk_archive(libs: &Vec<PathBuf>) {
//     fs::create_dir_all("tmp").expect("Unable to create tmp directory under project directory. Please check your permissions.");
//     for path in libs.into_iter() {
//         if !path.is_file() || !path.exists() || path.is_dir() {
//             continue;
//         }
//
//         println!(
//             "Running command: ar -x {} in directory tmp",
//             path.display()
//         );
//
//         if let Err(e) = Command::new("ar")
//             .current_dir("tmp")
//             .arg("-x")
//             .arg(path.as_os_str())
//             .status() {
//             panic!("Unable to extract the object files of the {} static library to the tmp directory. Please check your permissions. Error: {}", &path.display(), e);
//         }
//     }
//
//     let entries = fs::read_dir("tmp")
//         .expect("Unable to read tmp directory in project directory.")
//         .filter_map(Result::ok)
//         .map(|entry| entry.path())
//         .filter(|path| path.is_file() && path.extension().and_then(std::ffi::OsStr::to_str) == Some("o")) // 过滤出 .o 文件
//         .map(|path| path.file_name().expect("Unable to obtain file name when filtering object files").to_str().unwrap().to_owned())
//         .collect::<Vec<String>>();
//
//     let mut command = Command::new("ar");
//     command
//         .current_dir("tmp")
//         .arg("-c")
//         .arg("-r")
//         .arg("-s")
//         .arg("-v")
//         .arg("../archive/libdpdk.a");
//     for entry in &entries {
//         command.arg(entry.clone());
//     }
//
//     // println!("Running command: ar -c -r -s -v archive/libdpdk.a {:#?}", &entries);
//     if let Err(e) = command
//         .status() {
//         panic!("Unable to create libdpdk.a static library into archive directory, please check your permissions. Error: {}", e);
//     }
//
//     fs::remove_dir_all("tmp")
//         .expect("Unable to delete the tmp directory under the project directory. Please check your permissions.");
//
//     fs::write(Path::new("archive/.hash"), sha256("/usr/local/include/rte_config.h"))
//         .expect("Unable to write .hash file under archive directory. Please check your permissions.");
//
//     let date = fs::metadata(Path::new("/usr/local/include/rte_config.h"))
//         .expect("Unable to get metadata of the rte_config.h file. Please check your permissions.")
//         .modified()
//         .expect("Unable to get modified time of the rte_config.h file. Please check your permissions.");
//
//     fs::write(Path::new("archive/.date"), format!("{:?}", date))
//         .expect("Unable to write .cache file under archive directory. Please check your permissions.");
// }

// fn prepare_dpdk() -> bool {
//     let dpdk = pkg_config::Config::new()
//         .arg("--static")
//         .probe("libdpdk")
//         .expect("libdpdk is not installed. Please install libdpdk first.");
//
//     let mut link_paths = dpdk.link_paths.clone();
//     link_paths.sort();
//     link_paths.dedup();
//     for link_path in link_paths.iter() {
//         println!("cargo:rustc-link-search={}", link_path.display());
//     }
//
//     let mut all_static_libs = vec![];
//     for path in link_paths.iter() {
//         for lib in dpdk.libs.iter() {
//             if lib.is_empty() {
//                 continue;
//             }
//             if lib.contains(".a") {
//                 // collect static library
//                 let library = path.clone().join(lib.clone().replace(":", ""));
//                 all_static_libs.push(library);
//             } else {
//                 // link dynamic library
//                 println!("cargo:rustc-link-lib=dylib={}", lib);
//             }
//         }
//     }
//     all_static_libs.sort();
//     all_static_libs.dedup();
//
//     if !exists("archive") {
//         if !exists("archive") {
//             fs::create_dir_all("archive").expect("Unable to create archive directory under project directory. Please check your permissions.");
//         }
//         create_dpdk_archive(&all_static_libs);
//     }
//
//     if !exists("archive/libdpdk.a") {
//         create_dpdk_archive(&all_static_libs);
//     }
//
//     if changed() {
//         create_dpdk_archive(&all_static_libs);
//     } else {
//         println!("No changes in dpdk library, skip building.");
//     }
//
//     exists("archive/libdpdk.a")
// }

fn main() {
    println!("cargo::rerun-if-changed=build.rs");
    println!("cargo::rerun-if-changed=/usr/local/include/ff_api.h");
    println!("cargo::rerun-if-changed=/usr/local/include/ff_config.h");
    println!("cargo::rerun-if-changed=/usr/local/include/ff_epoll.h");
    println!("cargo::rerun-if-changed=/usr/local/include/ff_errno.h");
    println!("cargo::rerun-if-changed=/usr/local/include/ff_event.h");
    println!("cargo::rerun-if-changed=/usr/local/lib/libfstack.a");

    let bindings = bindgen::Builder::default()
        .layout_tests(false)
        .clang_arg("-I/usr/local/include")
        .formatter(Formatter::Prettyplease)
        // .raw_line("#[allow(unsafe_op_in_unsafe_fn)]")
        .wrap_unsafe_ops(true)
        .generate_comments(true)
        .headers([
            "/usr/local/include/ff_api.h",
            "/usr/local/include/ff_config.h",
            "/usr/local/include/ff_epoll.h",
            "/usr/local/include/ff_errno.h",
            "/usr/local/include/ff_event.h",
            "/usr/include/arpa/inet.h",
        ])
        .generate()
        .expect("Unable to generate bindings");
    bindings
        .write_to_file("src/bindings.rs")
        .expect("Couldn't write bindings!");

    if !exists("/usr/local/lib/x86_64-linux-gnu/librte_acl.a"){
        if !exists("/usr/local/lib/librte_acl.a"){
            panic!("libdpdk is not installed. Please install libdpdk first.");
        }
    }

    // import library search path
    println!("cargo:rustc-link-search=native=/usr/local/lib");
    println!("cargo:rustc-link-search=native=/usr/local/lib/dpdk");
    println!("cargo:rustc-link-search=native=/usr/lib/x86_64-linux-gnu");
    println!("cargo:rustc-link-search=native=/usr/local/lib/x86_64-linux-gnu");

    // import library libfstack.a
    println!("cargo:rustc-link-lib=static=fstack");

    // 导入dpdk相关依赖库、切记不要修改导入顺序
    println!("cargo:rustc-link-lib=dylib=rte_bus_pci");
    println!("cargo:rustc-link-lib=dylib=rte_bus_vdev");
    println!("cargo:rustc-link-lib=dylib=rte_net_bond");
    // println!("cargo:rustc-link-lib=dylib=rte_net_i40e");
    println!("cargo:rustc-link-lib=dylib=rte_timer");
    println!("cargo:rustc-link-lib=dylib=rte_hash");
    println!("cargo:rustc-link-lib=dylib=rte_pci");
    println!("cargo:rustc-link-lib=dylib=rte_ethdev");
    println!("cargo:rustc-link-lib=dylib=rte_net");
    println!("cargo:rustc-link-lib=dylib=rte_mbuf");
    println!("cargo:rustc-link-lib=dylib=rte_mempool");
    println!("cargo:rustc-link-lib=dylib=rte_rcu");
    println!("cargo:rustc-link-lib=dylib=rte_ring");
    println!("cargo:rustc-link-lib=dylib=rte_eal");
    println!("cargo:rustc-link-lib=dylib=rte_telemetry");
    println!("cargo:rustc-link-lib=dylib=rte_kvargs");
    println!("cargo:rustc-link-lib=dylib=rte_log");

    println!("cargo:rustc-link-lib=dylib=archive");
    println!("cargo:rustc-link-lib=dylib=nettle");
    println!("cargo:rustc-link-lib=dylib=acl");
    println!("cargo:rustc-link-lib=dylib=lzma");
    println!("cargo:rustc-link-lib=dylib=zstd");
    println!("cargo:rustc-link-lib=dylib=lz4");
    println!("cargo:rustc-link-lib=dylib=bz2");
    println!("cargo:rustc-link-lib=dylib=z");
    println!("cargo:rustc-link-lib=dylib=xml2");

    println!("cargo:rustc-link-lib=dylib=rt");
    println!("cargo:rustc-link-lib=dylib=m");
    println!("cargo:rustc-link-lib=dylib=dl");
    println!("cargo:rustc-link-lib=dylib=crypto");
    println!("cargo:rustc-link-lib=dylib=pthread");
    println!("cargo:rustc-link-lib=dylib=numa");

    // println!("cargo:rustc-link-arg=-Wl,--whole-archive,-l:libfstack.a,-l:librte_bus_pci.a,-l:librte_bus_vdev.a,-l:librte_net_bond.a,-l:librte_net_i40e.a,-l:librte_timer.a,-l:librte_hash.a,-l:librte_pci.a,-l:librte_ethdev.a,-l:librte_net.a,-l:librte_mbuf.a,-l:librte_mempool.a,-l:librte_rcu.a,-l:librte_ring.a,-l:librte_eal.a,-l:librte_telemetry.a,-l:librte_kvargs.a,-l:librte_log.a,-l:libarchive.a,-l:libnettle.a,-l:libacl.a,-l:liblzma.a,-l:libzstd.a,-l:liblz4.a,-l:libbz2.a,-l:libz.a,-l:libxml2.a,-l:libicuuc.a,-l:libicudata.a,-l:libnuma.a,-l:librt.a,-l:libcrypto.a");
    // println!("cargo:rustc-link-arg=-larchive,-lnettle,-lacl,-llzma,-lzstd,-llz4,-lbz2,-lz,-lxml2,-lrt,-lm,-ldl,-lcrypto,-lpthread,-lnuma");
    // println!("cargo:rustc-link-lib=static:+whole-archive=dpdk");
    // env::set_var("RUSTFLAGS", "-C link-arg=-Wl,-z,nostart-stop-gc --allow-multiple-definition");
    // println!("cargo:rustc-link-arg=-Wl,-z,nostart-stop-gc");
}
