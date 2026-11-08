package ipc
import(
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"
)
type replyFailure struct{*bytes.Reader}
func(replyFailure)Write([]byte)(int,error){return 0,errors.New("fixture write failed")}
func TestAfterReplyRunsOnlyAfterWriteResultAndPasswordPayloadIsCleared(t *testing.T){
	for _,fail:=range []bool{false,true}{
		var frame bytes.Buffer
		Write(&frame,Request{Version:1,ID:"fixture",SentAt:time.Now(),Token:"01234567890123456789012345678901ab",Method:"emergency.finish",Payload:json.RawMessage(`{"fixture":true}`)})
		var captured json.RawMessage
		server,_:=New("01234567890123456789012345678901ab",func(_ context.Context,_ string,raw json.RawMessage)(any,error){captured=raw;return "confirmed",nil})
		called:=false
		server.AfterReply=func(method string,reply Response,writeError error){
			called=true
			if method!="emergency.finish"||!reply.OK||(writeError!=nil)!=fail{t.Error("incorrect write observation")}
			if !fail&&frame.Len()==0{t.Error("hook before response write")}
		}
		var err error
		if fail{err=server.Serve(context.Background(),replyFailure{bytes.NewReader(frame.Bytes())})}else{err=server.Serve(context.Background(),&frame)}
		if !called||(err!=nil)!=fail{t.Fatal("missing completion hook")}
		for _,b:=range captured{if b!=0{t.Fatal("request payload retained")}}
	}
}
