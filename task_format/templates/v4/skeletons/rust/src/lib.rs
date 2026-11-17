//! The application (TODO(builder)).

/// Answers one request.
pub fn handle(request: &str) -> String {
    format!("{{\"answer\": \"TODO: handle {}\"}}", request.replace('"', "'"))
}
