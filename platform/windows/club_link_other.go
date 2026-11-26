//go:build !windows

package windowsplatform

func PassiveClubLinks() (ClubLinkSnapshot, error) { return ClubLinkSnapshot{}, ErrUnavailable }
