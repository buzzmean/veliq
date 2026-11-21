//go:build !windows

package windowsplatform

func EdgeProxyPolicyWrite(string, []string, string) error { return ErrUnavailable }
func EdgeProxyPolicyActive(string, string) bool           { return false }

func ChromeProxyPolicyWrite(string, []string, string) error { return ErrUnavailable }
func ChromeProxyPolicyRemove(string, []string) error        { return ErrUnavailable }
func EdgeProxyPolicyRemove(string, []string) error          { return ErrUnavailable }
