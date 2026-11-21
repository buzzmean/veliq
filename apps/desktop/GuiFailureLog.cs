using System.Text.Json;
namespace Neexitlag.Desktop;
public partial class MainWindow {
 void InitializeGuiFailureLog(){
  model.GuiFailureReported+=failure=>{
   // No exception message, stack, IPC payload or recovery configuration. Safe
   // for the owner to share; writing failure cannot break GUI availability.
   try{
    var directory=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),"VELIQ");
    Directory.CreateDirectory(directory);
    var path=Path.Combine(directory,"gui-failure.json");var temp=path+".tmp";
    File.WriteAllText(temp,JsonSerializer.Serialize(failure,WireJson.Options));File.Move(temp,path,true);
   }catch(IOException){}catch(UnauthorizedAccessException){}
  };
 }
}
