package engine

import "golang.org/x/sys/windows"

// portBusy reports whether another program listens on TCP port on any
// address. Windows lets us bind 127.0.0.1:port even when someone has
// 0.0.0.0:port, silently taking their local connections, so try binding the
// wildcard address instead (bind only: no listen, no connection, no firewall
// prompt).
func portBusy(port int) bool {
	s, err := windows.Socket(windows.AF_INET, windows.SOCK_STREAM, windows.IPPROTO_TCP)
	if err != nil {
		return false
	}
	defer func() { _ = windows.Closesocket(s) }()
	return windows.Bind(s, &windows.SockaddrInet4{Port: port}) != nil
}
