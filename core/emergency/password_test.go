package emergency

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/buzzmean/neexitlag/core/ipc"
)

func fixture(t *testing.T) (*Authenticator,[]byte) {
	t.Helper()
	password:=[]byte("fixture-only-password")
	record,err:=Create(password,"owner-fixture")
	if err!=nil {t.Fatal(err)}
	raw,_:=json.Marshal(record)
	return New("owner-fixture",func()([]byte,error){return bytes.Clone(raw),nil}),password
}
func TestOfflineVerifierAndOwnerBinding(t *testing.T) {
	a,password:=fixture(t)
	if !a.Configured() || a.Verify(password)!=nil {t.Fatal("offline verifier rejected")}
	if !errors.Is(a.Verify([]byte("wrong")),ErrPassword) {t.Fatal("wrong password accepted")}
	raw,_:=a.load()
	if _,err:=Decode(raw,"different-owner");err==nil {t.Fatal("foreign owner accepted")}
	for _,raw:=range [][]byte{nil,[]byte("{}"),append(raw,[]byte("{}")...)} {
		if _,err:=Decode(raw,"owner-fixture");err==nil {t.Fatal("malformed verifier accepted")}
	}
	missing:=New("owner",func()([]byte,error){return nil,os.ErrNotExist})
	if missing.Configured() || !errors.Is(missing.Verify(password),ErrNotConfigured) {t.Fatal("missing verifier")}
}
func TestVerifierRateLimitAndConcurrentChecks(t *testing.T) {
	a,password:=fixture(t)
	now:=time.Date(2026,1,1,0,0,0,0,time.UTC);a.now=func()time.Time{return now}
	for i:=0;i<maxFailures;i++ {if !errors.Is(a.Verify([]byte("wrong")),ErrPassword){t.Fatal("failure not counted")}}
	if !errors.Is(a.Verify(password),ErrRateLimited){t.Fatal("lockout bypassed")}
	now=now.Add(lockDuration)
	if err:=a.Verify(password);err!=nil {t.Fatal(err)}
	var wg sync.WaitGroup
	for i:=0;i<4;i++ {wg.Add(1);go func(){defer wg.Done();if a.Verify(password)!=nil {t.Error("concurrent valid request")}}()}
	wg.Wait()
}
func TestManagerNeverStopsForWrongPasswordAndConfirmsOnlyAfterCleanup(t *testing.T) {
	a,password:=fixture(t)
	started,release,done:=make(chan struct{}),make(chan struct{}),make(chan struct{})
	var count atomic.Int32
	m:=NewManager(a,func()error{count.Add(1);close(started);<-release;close(done);return nil})
	m.IdleStatus=func()any{return "watchdog-readable"}
	h:=m.Wrap(func(context.Context,string,json.RawMessage)(any,error){return nil,errors.New("ordinary gated")})
	wrong,_:=json.Marshal(map[string][]byte{"password":[]byte("wrong")})
	if _,err:=h(context.Background(),"emergency.stop",wrong);!errors.Is(err,ErrPassword)||count.Load()!=0 {t.Fatal("wrong password changed state")}
	if _,err:=h(context.Background(),"emergency.finish",nil);err==nil {t.Fatal("early finish")}
	raw,_:=json.Marshal(map[string][]byte{"password":password})
	if _,err:=h(context.Background(),"emergency.stop",raw);err!=nil {t.Fatal(err)}
	for _,b:=range raw {if b!=0 {t.Fatal("password request retained")}}
	<-started
	if m.Status().State!="STOPPING"{t.Fatal("premature success")}
	if got,err:=h(context.Background(),"status",nil);err!=nil||got!="watchdog-readable"{t.Fatal("watchdog blind during cleanup")}
	if _,err:=h(context.Background(),"optimize",nil);err==nil {t.Fatal("mutation admitted")}
	close(release);<-done
	for deadline:=time.Now().Add(time.Second);m.Status().State=="STOPPING"&&time.Now().Before(deadline);{time.Sleep(time.Millisecond)}
	if m.Status().State!="STOPPED" {t.Fatal("missing completion")}
	if _,err:=h(context.Background(),"emergency.finish",nil);err!=nil {t.Fatal(err)}
	if count.Load()!=1 {t.Fatal("cleanup repeated")}
}
func TestManagerCleanupFailureAndCancelledRequest(t *testing.T) {
	a,password:=fixture(t);var count atomic.Int32
	m:=NewManager(a,func()error{count.Add(1);return errors.New("fixture failure")})
	h:=m.Wrap(nil)
	ctx,cancel:=context.WithCancel(context.Background());cancel()
	raw,_:=json.Marshal(map[string][]byte{"password":password})
	if _,err:=h(ctx,"emergency.stop",raw);err==nil||count.Load()!=0 {t.Fatal("cancelled request mutated")}
	raw,_=json.Marshal(map[string][]byte{"password":password})
	if _,err:=h(context.Background(),"emergency.stop",raw);err!=nil {t.Fatal(err)}
	for deadline:=time.Now().Add(time.Second);m.Status().State=="STOPPING"&&time.Now().Before(deadline);{time.Sleep(time.Millisecond)}
	if m.Status().State!="CLEANUP_FAILED" {t.Fatal("failed cleanup reported stopped")}
	if _,err:=h(context.Background(),"emergency.finish",nil);err==nil {t.Fatal("failure allowed finish")}
}
func TestIPCAuthenticationPrecedesEmergencyPassword(t *testing.T) {
	a,password:=fixture(t);var count atomic.Int32
	manager:=NewManager(a,func()error{count.Add(1);return nil})
	server,_:=ipc.New("01234567890123456789012345678901ab",manager.Wrap(nil))
	raw,_:=json.Marshal(map[string][]byte{"password":password})
	reply:=server.Execute(context.Background(),ipc.Request{Version:1,ID:"fixture",SentAt:time.Now(),Token:"foreign",Method:"emergency.stop",Payload:raw},time.Now())
	if reply.OK || count.Load()!=0 {t.Fatal("IPC authentication bypassed")}
}
