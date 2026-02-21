fn main() {
    // ── SP1 guest ELF compilation (only when the `zk` feature is active) ─────
    //
    // When `cargo build --features zk` is invoked, sp1_build compiles the guest RISC-V
    // program at `crates/guest/` and makes its ELF available to the host via an env var
    // (`IRONCLAD_GUEST_ELF_PATH`) that is set in the cargo build script output.
    // The host `prove-audit` command includes this ELF at compile time.
    #[cfg(feature = "zk")]
    {
        sp1_build::build_program("../guest");
    }

    // ── Windows icon embedding (non-ZK-gated) ────────────────────────────────
    #[cfg(target_os = "windows")]
    embed_windows_icon();
}

#[cfg(target_os = "windows")]
fn embed_windows_icon() {
    use std::env;
    use std::fs::File;
    use std::io::{BufWriter, Write};
    use std::path::Path;

    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    // The crate lives in `crates/host` whereas the logo lives at the workspace
    // root (`assets/logo.png`).  On Windows CI we were failing because we tried
    // to open `crates/host/assets/logo.png` which doesn't exist.  Climb two
    // levels to reach the workspace root.
    let logo_path = Path::new(&manifest_dir)
        .join("..")
        .join("..")
        .join("assets")
        .join("logo.png");

    if !logo_path.exists() {
        eprintln!("warning: windows icon not generated because {} does not exist", logo_path.display());
        return;
    }

    let out_dir = env::var("OUT_DIR").unwrap();
    let ico_path = Path::new(&out_dir).join("icon.ico");

    let img = image::open(&logo_path).expect("failed to open assets/logo.png");
    let rgba = img.to_rgba8();
    let (w, h) = (rgba.width(), rgba.height());
    let sizes = [256u32, 48, 32, 16];

    let mut icon_dir = ico::IconDir::new(ico::ResourceType::Icon);
    for size in sizes {
        if w >= size && h >= size {
            let resized = image::imageops::resize(
                &rgba,
                size,
                size,
                image::imageops::FilterType::Lanczos3,
            );
            let raw = resized.into_raw();
            let icon_img = ico::IconImage::from_rgba_data(size, size, raw);
            let entry = ico::IconDirEntry::encode(&icon_img).expect("encode icon entry");
            icon_dir.add_entry(entry);
        }
    }
    if icon_dir.entries().is_empty() {
        let raw = rgba.into_raw();
        let icon_img = ico::IconImage::from_rgba_data(w, h, raw);
        let entry = ico::IconDirEntry::encode(&icon_img).expect("encode icon entry");
        icon_dir.add_entry(entry);
    }

    let file = File::create(&ico_path).expect("create icon file");
    let mut writer = BufWriter::new(file);
    icon_dir.write(&mut writer).expect("write ico");
    writer.flush().expect("flush icon file");

    winres::WindowsResource::new()
        .set_icon(ico_path.to_str().unwrap())
        .compile()
        .expect("winres compile");
}
