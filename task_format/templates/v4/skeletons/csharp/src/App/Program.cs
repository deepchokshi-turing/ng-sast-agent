namespace App;

public static class Handler
{
    public static string Handle(string request) => $"{{\"answer\": \"TODO: handle {request.Replace("\"", "'")}\"}}";
}

public static class Program
{
    public static int Main(string[] args)
    {
        var request = args.Length == 0 ? "hello" : string.Join(' ', args);
        Console.WriteLine(Handler.Handle(request));
        return 0;
    }
}
