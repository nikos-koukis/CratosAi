package clients

import "testing"

func TestDeviceAddressesStayOnTheTailnet(t *testing.T) {
	strict, dev := DeviceGuard{}, DeviceGuard{AllowLoopback: true}
	for _, ok := range []string{"100.64.0.1:7443", "100.127.255.254:7443", "[fd7a:115c:a1e0::1]:7443", "mac.tail1234.ts.net:7443"} {
		if err := strict.CheckAddress(ok); err != nil {
			t.Errorf("%s refused: %v", ok, err)
		}
	}
	for _, bad := range []string{"127.0.0.1:7443", "localhost:7443", "10.0.0.1:7443", "192.168.1.2:7443", "8.8.8.8:7443",
		"100.128.0.1:7443", "example.com:7443", "169.254.169.254:80", "[::1]:7443", "100.64.0.1", ":7443"} {
		if err := strict.CheckAddress(bad); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
	if dev.CheckAddress("127.0.0.1:7443") != nil || dev.CheckAddress("localhost:7443") != nil {
		t.Error("development loopback refused")
	}
}
