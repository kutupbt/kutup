fn main() {
    // `sqlx::migrate!()` embeds migrations in the server binary. Cargo does
    // not otherwise know that files outside `src/` are compile inputs, which
    // can leave a cached container binary running an obsolete fresh schema.
    println!("cargo:rerun-if-changed=migrations");
}
