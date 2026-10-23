package main

import (
	"syscall"
	"unsafe"
)

// The local terminal, through the same kind of ioctls the agent uses for
// the PTY. No library: the CLI stays dependency-free.

func ioctl(fd int, req uintptr, arg unsafe.Pointer) error {
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), req, uintptr(arg)); errno != 0 {
		return errno
	}
	return nil
}

// isTerminal reports whether fd is a terminal: getting its settings works
// only if it is.
func isTerminal(fd int) bool {
	var t syscall.Termios
	return ioctl(fd, syscall.TCGETS, unsafe.Pointer(&t)) == nil
}

// makeRaw switches the terminal to raw mode and returns a function that
// restores the original settings.
//
// A terminal normally works in "cooked" mode: the kernel buffers a line
// until Enter, handles backspace itself, echoes what you type, and turns
// Ctrl+C into SIGINT for *this* process. For a remote shell, all of that
// must happen on the other side instead, so raw mode switches it all off
// here: every byte goes straight through, Ctrl+C included.
func makeRaw(fd int) (func(), error) {
	var old syscall.Termios
	if err := ioctl(fd, syscall.TCGETS, unsafe.Pointer(&old)); err != nil {
		return nil, err
	}
	raw := old
	raw.Iflag &^= syscall.IGNBRK | syscall.BRKINT | syscall.PARMRK | syscall.ISTRIP |
		syscall.INLCR | syscall.IGNCR | syscall.ICRNL | syscall.IXON
	raw.Oflag &^= syscall.OPOST
	raw.Lflag &^= syscall.ECHO | syscall.ECHONL | syscall.ICANON | syscall.ISIG | syscall.IEXTEN
	raw.Cflag &^= syscall.CSIZE | syscall.PARENB
	raw.Cflag |= syscall.CS8
	raw.Cc[syscall.VMIN] = 1  // a read returns as soon as one byte is there
	raw.Cc[syscall.VTIME] = 0 // with no timeout
	if err := ioctl(fd, syscall.TCSETS, unsafe.Pointer(&raw)); err != nil {
		return nil, err
	}
	return func() { _ = ioctl(fd, syscall.TCSETS, unsafe.Pointer(&old)) }, nil
}

type winsize struct{ Rows, Cols, X, Y uint16 }

func termSize(fd int) (cols, rows uint16, err error) {
	var ws winsize
	if err := ioctl(fd, syscall.TIOCGWINSZ, unsafe.Pointer(&ws)); err != nil {
		return 0, 0, err
	}
	return ws.Cols, ws.Rows, nil
}
