package clientservice

import (
	"context"
	"fmt"
	"sync"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/buzzmean/veliq/core/optimizer"
	"github.com/buzzmean/veliq/core/routing"
	"github.com/buzzmean/veliq/core/transport"
)

type fleetSelectionPool struct {
	calls int
	err error
}

func (p *fleetSelectionPool) OpenFleetTCP(context.Context, netip.AddrPort) (net.Conn, error) {
	p.calls++
	if p.err != nil {
		return nil, p.err
	}
	a,b := net.Pipe()
	_ = b.Close()
	return a,nil
}

func (p *fleetSelectionPool) OpenFleetDatagram(context.Context, netip.AddrPort) (routing.Datagram, error) {
	p.calls++
	if p.err != nil {
		return nil,p.err
	}
	return selectionDatagram{}, nil
}

type selectionDatagram struct{}

func (selectionDatagram) Close() error { return nil }
func (selectionDatagram) Send([]byte) error { return nil }
func (selectionDatagram) Receive(context.Context) ([]byte,error) { return []byte{1},nil }

func fleetFixture(t *testing.T) (*relayFleet, time.Time, []fleetNode, *fleetSelectionPool, *fleetSelectionPool) {
	t.Helper()
	now := time.Unix(1000,0)
	f := newRelayFleet(func() string {return "fixture-network"})
	f.now = func() time.Time {return now}
	f.arm("fixture-device")
	a,b := &fleetSelectionPool{}, &fleetSelectionPool{}
	nodes := []fleetNode{{id:"A", address:"127.0.0.1:1", weight:0.1, observed:now, pool:a},{id:"B", address:"127.0.0.1:2", weight:1, observed:now,pool:b}}
	f.configure(1,now.Add(45*time.Second),true,nodes,"")
	for i, node := range nodes {
		rtt := time.Duration(12+80*i)*time.Millisecond
		for round:=0;round<4;round++ {
			at:=now.Add(time.Duration(round-4)*time.Second)
			probes := make([]optimizer.ProbeSample,5)
			for j := range probes { probes[j] = optimizer.ProbeSample{At:at,RTT:rtt,Outcome:optimizer.Reply} }
			f.observe(optimizer.RouteMeasurement{RouteID:node.id,RouteAddress:node.address,Network:"fixture-network",AuthenticatedTarget:true,Available:true,ObservedAt:at,Samples:5,RTT:rtt,Probes:probes,Stability:1})
		}
	}
	return f,now,nodes,a,b
}

func TestFleetAffinitySurvivesRefreshAndPreventsSplit(t *testing.T) {
	f, now, nodes, _, standby := fleetFixture(t)
	ctx := context.Background()
	flow:=routing.Flow{Destination:netip.MustParseAddrPort("198.51.100.9:443")}
	tcp,id,err:=f.OpenTCP(ctx,flow)
	if err!=nil||id!="A"{t.Fatalf("latency should outrank free capacity: %s / %v",id,err)}
	udp,id,err:=f.OpenDatagram(ctx,flow)
	if err!=nil||id!="A"{t.Fatalf("related UDP went to another egress: %s / %v",id,err)}
	_ = udp.Close()
	f.configure(2,now.Add(fleetLoadTTL),true,nodes[1:],"")
	if _,_,err=f.OpenDatagram(ctx,flow); transport.FailureReason(err)!="fleet_affinity_unavailable"||standby.calls!=0{
		t.Fatalf("removed node silently split a live group: %v",err)
	}
	_ = tcp.Close()
	udp,id,err=f.OpenDatagram(ctx,flow)
	if err!=nil||id!="B"{t.Fatalf("new group could not select its available relay: %s / %v",id,err)}
	_ = udp.Close()
	f.now=func()time.Time{return now.Add(fleetLoadTTL)}
	if _,_,err=f.OpenDatagram(ctx,flow);transport.FailureReason(err)!="fleet_policy_unavailable"{
		t.Fatalf("expired policy was used: %v",err)
	}
}

func TestFleetRetriesOnlyAdmissibleNewOpens(t *testing.T) {
	for _, scenario:=range []struct{reason string;retry bool}{{"relay_flow_capacity",true},{"admission_timeout",true},{"upstream_dial_failed",true},{"session_network_unavailable",true},{"ticket_request_failed",false},{"authorization_expired_or_revoked",false},{"relay_destination_denied",false}}{
		t.Run(scenario.reason,func(t *testing.T){
			f,_,_,a,b:=fleetFixture(t)
			a.err=&transport.OpenError{Reason:scenario.reason}
			conn,id,err:=f.OpenTCP(context.Background(),routing.Flow{Destination:netip.MustParseAddrPort("198.51.100.7:443")})
			if scenario.retry {
				if err!=nil||id!="B"||a.calls!=1||b.calls!=1{t.Fatalf("retry outcome %v/%s, calls %d/%d",err,id,a.calls,b.calls)}
				_ = conn.Close()
			} else if err==nil||a.calls!=1||b.calls!=0 {
				t.Fatalf("terminal failure was retried: %v / %d / %d",err,a.calls,b.calls)
			}
		})
	}
}

func TestFleetShortlistRetainsBoundNodeAndIncludesScopedCanary(t *testing.T) {
	f, now, nodes, _, _ := fleetFixture(t)
	flow := routing.Flow{Destination: netip.MustParseAddrPort("198.51.100.4:443")}
	conn, id, err := f.OpenTCP(context.Background(), flow)
	if err != nil || id != "A" {
		t.Fatalf("initial bind: %s, %v", id, err)
	}
	defer conn.Close()
	all := append(nodes, fleetNode{id: "C", address: "127.0.0.1:3", canary: true, weight: 1, observed: now})
	chosen := f.shortlist(all, "fixture-network")
	if len(chosen) != fleetCandidateLimit || chosen[0].id != id || chosen[1].id != "C" {
		t.Fatalf("shortlist did not keep bound node and scoped canary: %+v", chosen)
	}
}

func TestFleetConcurrentDeviceFixturesKeepOneComparableEgress(t *testing.T) {
	for _, count := range []int{10, 40, 120} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			var work sync.WaitGroup
			results := make(chan string, count)
			for i := 0; i < count; i++ {
				work.Add(1)
				go func() {
					defer work.Done()
					now := time.Unix(1000, 0)
					f := newRelayFleet(func() string { return "fixture-LAN" })
					f.now = func() time.Time { return now }
					f.arm(fmt.Sprintf("device-%d", i))
					nodes := []fleetNode{
						{id: "A", address: "127.0.0.1:1", weight: 1, observed: now, pool: &fleetSelectionPool{}},
						{id: "B", address: "127.0.0.1:2", weight: .5, observed: now, pool: &fleetSelectionPool{}},
					}
					f.configure(1, now.Add(time.Minute), true, nodes, "")
					for _, node := range nodes {
						for round := 0; round < 4; round++ {
							at := now.Add(time.Duration(round-4)*time.Second)
							probes := make([]optimizer.ProbeSample, 5)
							for j := range probes {
								probes[j] = optimizer.ProbeSample{At: at, RTT: 20*time.Millisecond, Outcome: optimizer.Reply}
							}
							f.observe(optimizer.RouteMeasurement{RouteID: node.id, RouteAddress: node.address, Network: "fixture-LAN",
								AuthenticatedTarget: true, Available: true, ObservedAt: at, Samples: 5, RTT: 20*time.Millisecond, Probes: probes, Stability: 1})
						}
					}
					tcp, first, err := f.OpenTCP(context.Background(), routing.Flow{Destination: netip.MustParseAddrPort("198.51.100.9:443")})
					if err != nil {
						results <- ""
						return
					}
					defer tcp.Close()
					udp, second, err := f.OpenDatagram(context.Background(), routing.Flow{Destination: netip.MustParseAddrPort("198.51.100.10:5000")})
					if err != nil || first != second {
						results <- ""
						return
					}
					defer udp.Close()
					results <- first
				}()
			}
			work.Wait()
			close(results)
			chosen := map[string]int{}
			for id := range results {
				chosen[id]++
			}
			if chosen[""] != 0 || chosen["A"] <= chosen["B"] || chosen["B"] == 0 {
				t.Fatalf("selection did not preserve weighted sharing and affinity: %v", chosen)
			}
		})
	}
}
