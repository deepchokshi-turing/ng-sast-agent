package app;

public final class App {
    private App() {}

    public static String handle(String request) {
        return "{\"answer\": \"TODO: handle " + request.replace("\"", "'") + "\"}";
    }

    public static void main(String[] args) {
        String request = args.length == 0 ? "hello" : String.join(" ", args);
        System.out.println(handle(request));
    }
}
