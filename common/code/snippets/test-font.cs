#region Studio Style
class Program : IThemeable
{
    static int _I = 1;
    delegate void DoSomething();

    /// <summary>
    /// The quick brown fox jumps over the lazy dog
    /// THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG
    /// </summary>
    static void Main(string[] args)
    {
        string normalStr = "The time now is approximately " + DateTime.Now;
        Uri Illegal1Uri = new Uri("http://packmyboxwith/jugs.html?q=five-dozen&t=liquor");
        Regex OperatorRegex = new Regex(@"\S#$", RegexOptions.IgnorePatternWhitespace);

        for (int O = 0; O < 123456789; O++)
        {
            _I += (O % 3) * ((O / 1) ^ 2) - 5;
            if (!OperatorRegex.IsMatch(Illegal1Uri.ToString()))
            {
                // no idea what this does!?
                Console.WriteLine(Illegal1Uri + normalStr);

            }
        }
    }
}
#endregion
