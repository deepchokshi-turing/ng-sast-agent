package app;

public final class SmokeTest {
    public static void main(String[] args) {
        if (App.handle("hello").isEmpty()) {
            throw new AssertionError("empty answer");
        }
        System.out.println("OK");
    }
}
