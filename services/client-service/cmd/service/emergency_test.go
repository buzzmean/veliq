package main

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/buzzmean/neexitlag/core/emergency"
	clientservice "github.com/buzzmean/neexitlag/services/client-service"
)

func TestEmergencyWorksBeforeControlPlaneStartupAndDoesNotOpenOtherMethods(t *testing.T) {
	record,err:=emergency.Create([]byte("fixture-password"),"fixture-owner")
	if err!=nil {t.Fatal(err)}
	encoded,_:=json.Marshal(record)
	auth:=emergency.New("fixture-owner",func()([]byte,error){return append([]byte(nil),encoded...),nil})
	controller:=clientservice.New(context.Background())
	defer controller.Close()
	var gate startupGate
	gate.emergencyStopping=controller.EmergencyStopping
	ctx,cancel:=context.WithCancel(context.Background())
	defer cancel()
	done:=make(chan struct{})
	go func(){<-ctx.Done();close(done)}() // blocked CP initialization fixture
	manager:=emergency.NewManager(auth,func()error{
		controller.BeginEmergencyStop()
		cancel()
		<-done
		return controller.FinishEmergencyStop()
	})
	controller.ConfigureEmergencyManager(manager)
	// Same chain as runReady: authenticated IPC -> startup -> owner -> controller.
	h:=gate.wrap(controller.HandleOwnerIPC)
	if _,err:=h(context.Background(),"optimize",nil);!errors.Is(err,errStarting){t.Fatal("startup gate weakened")}
	if value,err:=h(context.Background(),"emergency.status",nil);err!=nil||!value.(emergency.Status).Configured{t.Fatal("offline status blocked")}
	raw,_:=json.Marshal(map[string][]byte{"password":[]byte("fixture-password")})
	if _,err:=h(context.Background(),"emergency.stop",raw);err!=nil {t.Fatal(err)}
	for deadline:=time.Now().Add(time.Second);manager.Status().State=="STOPPING"&&time.Now().Before(deadline);{time.Sleep(time.Millisecond)}
	if manager.Status().State!="STOPPED" {t.Fatal("startup emergency did not complete")}
	if _,err:=h(context.Background(),"status",nil);err!=nil {t.Fatal("watchdog status unavailable")}
	if _,err:=h(context.Background(),"emergency.finish",nil);err!=nil {t.Fatal("finish not dispatched")}
	if _,err:=h(context.Background(),"optimize",[]byte(`{"enabled":true}`));err==nil {t.Fatal("ordinary mutation allowed")}
}
