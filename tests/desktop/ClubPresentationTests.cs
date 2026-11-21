using Neexitlag.Desktop;
using Xunit;
public class ClubPresentationTests
{
 [Fact] public void ClubMarkerRequiresExplicitVersionAndEnable(){Assert.True(ClubPresentation.Enabled("{\"version\":1,\"enabled\":true}"));foreach(var v in new[]{"{}","null","garbage","{\"version\":2,\"enabled\":true}","{\"version\":1,\"enabled\":false}"})Assert.False(ClubPresentation.Enabled(v));}
 [Theory][InlineData(false,true,true)][InlineData(true,false,true)][InlineData(true,true,false)]public void PartialReadinessIsNotConnected(bool c,bool o,bool capture){Assert.Contains("подготовка",ClubPresentation.Summary(c,o,capture));}
 [Fact]public void AllRuntimeConditionsRequired(){Assert.Equal("VELIQ · защита включена",ClubPresentation.Summary(true,true,true));}
}
