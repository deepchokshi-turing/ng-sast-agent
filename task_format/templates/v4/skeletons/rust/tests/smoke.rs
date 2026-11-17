#[test]
fn runs() {
    assert!(!app::handle("hello").is_empty());
}
