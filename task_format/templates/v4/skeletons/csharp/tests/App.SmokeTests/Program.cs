if (string.IsNullOrEmpty(App.Handler.Handle("hello")))
{
    Console.Error.WriteLine("empty answer");
    return 1;
}
Console.WriteLine("OK");
return 0;
