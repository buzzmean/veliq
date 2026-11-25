using Veliq.Desktop;
using Xunit;
public class BrowserPreparingTests {
 [Fact] public void ReadyServiceConnectionDoesNotDependOnBrowser(){var s=new Snapshot{Connected=true,Optimizing=true,BrowserPolicy=new(){ChromeConfigured=true}};Assert.Equal(Text.Get("Connected"),ServiceConnectionText.Describe(s));s.BrowserPolicy.ChromeReady=true;Assert.Equal(Text.Get("Connected"),ServiceConnectionText.Describe(s));}
}
