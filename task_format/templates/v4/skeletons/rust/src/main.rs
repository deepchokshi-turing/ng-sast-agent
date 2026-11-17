fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let request = if args.is_empty() { "hello".to_string() } else { args.join(" ") };
    println!("{}", app::handle(&request));
}
