package windowsplatform

import (
	"net/netip"
	"testing"
)

func BenchmarkEvidencePacketAccounting(b *testing.B) {
	for _, parallel := range []bool{false, true} {
		for _,hotAttach:=range []bool{false,true} {
		name := "serial"
		if parallel {
			name = "parallel"
		}
		if hotAttach{name+="/hot_attach"}else{name+="/plain"}
		b.Run(name, func(b *testing.B) {
			ledger := NewEvidenceLedger()
			id := ProcessIdentity{PID: 16036, CreationTime: 134402359570643174, Path: `C:\Games\Warhammer\warhammer 40000 space marine 2 - retail.exe`}
			tuple := Tuple{Protocol: "udp", Source: netip.MustParseAddrPort("192.0.2.10:55000"), Destination: netip.MustParseAddrPort("203.0.113.20:27015")}
			ledger.BeginFlow(id, tuple)
			ledger.RecordBytes(id, tuple, "captured", "", 1200)
			if hotAttach{ledger.RecordHotAttach(id,tuple,1,"HOT_ATTACH_NEW_FLOW","revision");ledger.RecordBytes(id,tuple,"direct","",1200)}
			b.ReportAllocs()
			b.ResetTimer()
			if parallel {
				b.RunParallel(func(pb *testing.PB) {
					for pb.Next() {
						ledger.RecordBytes(id, tuple, "captured", "", 1200)
						ledger.RecordBytes(id, tuple, "direct", "", 1200)
					}
				})
			} else {
				for n := 0; n < b.N; n++ {
					ledger.RecordBytes(id, tuple, "captured", "", 1200)
					ledger.RecordBytes(id, tuple, "direct", "", 1200)
				}
			}
		})
		}
	}
}
