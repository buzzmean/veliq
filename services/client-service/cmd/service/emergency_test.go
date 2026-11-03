package main
import (
	"context"
	"encoding/json"
	"errors"
	"sync/atomic"
	"testing"
	"time"
	"github.com/buzzmean/neexitlag/core/emergency"
)
func TestEmergencyWorksBeforeControlPlaneStartupAndDoesNotOpenOtherMethods(t *testing.T) {
	record,err:=emergency.Create([]byte("fixture-password"),"fixture-owner");if err!=nil {t.Fatal(err)}
	encoded,_:=json.Marshal(record)
	auth:=emergency.New("fixture-owner",func()([]byte,error){return append([]byte(nil),encoded...),nil})
	var nextCalls atomic.Int32
	var gate startupGate
	ctx,cancel:=context.WithCancel(context.Background());defer cancel()
	done:=make(chan struct{})
	go func(){<-ctx.Done();close(done)}() // blocked network initialization fixture
	manager:=emergency.NewManager(auth,func()error{cancel();<-done;return nil})
	h:=manager.Wrap(gate.wrap(func(context.Context,string,json.RawMessage)(any,error){nextCalls.Add(1);return nil,nil}))
	if _,err:=h(context.Background(),"optimize",nil);!errors.Is(err,errStarting){t.Fatal("startup gate weakened")}
	if value,err:=h(context.Background(),"emergency.status",nil);err!=nil||!value.(emergency.Status).Configured{t.Fatal("offline status blocked")}
	raw,_:=json.Marshal(map[string][]byte{"password":[]byte("fixture-password")})
	if _,err:=h(context.Background(),"emergency.stop",raw);err!=nil {t.Fatal(err)}
	for deadline:=time.Now().Add(time.Second);manager.Status().State=="STOPPING"&&time.Now().Before(deadline);{time.Sleep(time.Millisecond)}
	if manager.Status().State!="STOPPED"||nextCalls.Load()!=0 {t.Fatal("startup emergency did not remain isolated")}
}
