package clientservice
import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"
	"github.com/buzzmean/neexitlag/core/emergency"
)
func TestEmergencyStopPreservesListenerUntilOwnedCleanupAndCannotReenable(t *testing.T) {
	c,value,_,_:=policyReadyFixture(t,false)
	*value="owned";c.browser.silent.Owned=[]string{"owned"}
	c.browser.chromeRemove=func(_ string,_ []string)error{
		if *value!="" && (c.browser.server==nil||!c.browser.server.Snapshot().Listening){t.Error("listener closed before restore")}
		*value="";return nil
	}
	c.BeginEmergencyStop()
	if err:=c.FinishEmergencyStop();err!=nil {t.Fatal(err)}
	if *value!=""||c.Backend.Status().Ready||c.activationNetworkAllowed(){t.Fatal("not fully stopped")}
	if _,err:=c.Handle(context.Background(),"optimize",[]byte(`{"enabled":true}`));err==nil {t.Fatal("re-enabled after emergency")}
	c.RetrySilentBrowserPolicies()
	if *value!="" {t.Fatal("policy reapplied")}
	c.Close() // idempotent, including the host defer
}
func TestEmergencyCleanupFailurePreservesForeignPolicy(t *testing.T) {
	c,value,_,_:=policyReadyFixture(t,false)
	*value="foreign";c.browser.silent.Owned=[]string{"ours"}
	c.browser.chromeRemove=func(_ string,_ []string)error{return errors.New("foreign preserved")}
	c.BeginEmergencyStop()
	if err:=c.FinishEmergencyStop();err==nil {t.Fatal("failed restore reported success")}
	if *value!="foreign" {t.Fatal("foreign setting overwritten")}
}
func TestClubEmergencyIsPasswordExceptionOnly(t *testing.T) {
	c:=New(context.Background());defer c.Close();c.Demo=true;c.clubMode.Store(true);c.enabled=true
	r,err:=emergency.Create([]byte("fixture-password"),"fixture-owner");if err!=nil {t.Fatal(err)}
	rawRecord,_:=json.Marshal(r)
	manager:=emergency.NewManager(emergency.New("fixture-owner",func()([]byte,error){return append([]byte(nil),rawRecord...),nil}),func()error{c.BeginEmergencyStop();return c.FinishEmergencyStop()})
	c.ConfigureEmergencyManager(manager)
	h:=c.HandleOwnerIPC
	if _,err:=h(context.Background(),"optimize",[]byte(`{"enabled":false}`));err==nil {t.Fatal("club mutation bypass")}
	raw,_:=json.Marshal(map[string][]byte{"password":[]byte("wrong")})
	if _,err:=h(context.Background(),"emergency.stop",raw);err==nil||!c.enabled {t.Fatal("wrong password stopped club")}
	raw,_=json.Marshal(map[string][]byte{"password":[]byte("fixture-password")})
	if _,err:=h(context.Background(),"emergency.stop",raw);err!=nil {t.Fatal(err)}
	for deadline:=time.Now().Add(time.Second);manager.Status().State=="STOPPING"&&time.Now().Before(deadline);{time.Sleep(time.Millisecond)}
	if manager.Status().State!="STOPPED" {t.Fatal(manager.Status().State)}
}
