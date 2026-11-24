package deviceinfo

import "testing"

func TestDeviceNameValidation(t *testing.T) {
	for _, name := range []string{"PC13", "ПК14", "CLUB-PC-02"} {
		if !(Details{ComputerName: name, Version: "0.3.735"}).Valid() {
			t.Fatal(name)
		}
	}
	for _, name := range []string{"", "PC13\n", "PC/13", "PC<13", " PC13"} {
		if (Details{ComputerName: name, Version: "0.3.735"}).Valid() {
			t.Fatal(name)
		}
	}
}

func TestDeviceDetailsProofBindsNameAndVersion(t *testing.T) {
	d := Details{ComputerName: "PC13", Version: "0.3.735"}
	if d.Audience() == (Details{ComputerName: "PC14", Version: d.Version}).Audience() ||
		d.Audience() == (Details{ComputerName: d.ComputerName, Version: "0.3.736"}).Audience() {
		t.Fatal("Содержимое не связано с подписью")
	}
	if len(d.Audience()) > 128 {
		t.Fatal("Слишком длинная аудитория подписи")
	}
}
