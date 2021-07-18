# RDPWrapInstaller

RDPWrapInstaller is an implementation of the [RDPWrapper](https://github.com/stascorp/rdpwrap) installer that allows you to programmatically manage the installation, uninstallation and other features of [RDPWrapper](https://github.com/stascorp/rdpwrap)

# Installing via NuGet (soon)

    Install-Package ...

## Usage
### Creating instance
```csharp
var rdpWrap = new RDPWrap();
```
### Install
```csharp
await rdpWrap.Install();
```
### Uninstall
```csharp
await rdpWrap.Uninstall();
```
### Reload
```csharp
await rdpWrap.Reload();
```
## Usage example
```csharp
private static RDPWrap _rdpWrap;
        
static async Task Main(string[] args)
{
    _rdpWrap = new RDPWrap();
    
    Console.WriteLine("I - install\n" +
                      "U - uninstall");
    Console.Write("Command: ");
    try
    {
        char cmd = Char.ToLower(Console.ReadKey().KeyChar);
        Console.WriteLine();
        var task = cmd switch
        {
            'i' => Install(),
            'u' => Uninstall(),
            _ => throw new ArgumentOutOfRangeException()
        };
        await task;
        Console.WriteLine("Command completed.");
    }
    catch (Exception ex)
    {
        Console.WriteLine("Error: " + ex);
    }

    Console.ReadLine();
}

private static async Task Install()
{
    if (!_rdpWrap.IsInstalled())
        await _rdpWrap.Install();
}

private static async Task Uninstall()
{
    if (_rdpWrap.IsInstalled())
        await _rdpWrap.Uninstall();
}
```

# License

RDPWrapInstaller is licensed under the [MIT](LICENSE) license.
