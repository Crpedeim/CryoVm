package guest

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

// openPTY creates a pseudo-terminal pair. The master is what we read and
// write; the slave, at the returned path, becomes the shell's terminal.
// Three steps, each one system call: open the multiplexer, ask which pair
// number the kernel allocated, and unlock the slave so it can be opened.
func openPTY() (master *os.File, slavePath string, err error) {
	m, err := os.OpenFile("/dev/ptmx", os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		return nil, "", fmt.Errorf("open /dev/ptmx: %w", err)
	}
	var n uint32
	if err := ioctl(m.Fd(), syscall.TIOCGPTN, uintptr(unsafe.Pointer(&n))); err != nil {
		m.Close()
		return nil, "", fmt.Errorf("TIOCGPTN: %w", err)
	}
	var unlock int32 // 0 means unlocked
	if err := ioctl(m.Fd(), syscall.TIOCSPTLCK, uintptr(unsafe.Pointer(&unlock))); err != nil {
		m.Close()
		return nil, "", fmt.Errorf("TIOCSPTLCK: %w", err)
	}
	return m, fmt.Sprintf("/dev/pts/%d", n), nil
}

// winsize is the kernel's struct winsize.
type winsize struct {
	Rows, Cols, X, Y uint16
}

// setWinsize tells the terminal its size. If it changed, the kernel sends
// SIGWINCH to the terminal's foreground process group, which is how vim
// and friends learn to redraw at the new size.
func setWinsize(f *os.File, cols, rows uint16) error {
	ws := winsize{Rows: rows, Cols: cols}
	return ioctl(f.Fd(), syscall.TIOCSWINSZ, uintptr(unsafe.Pointer(&ws)))
}

func getWinsize(f *os.File) (cols, rows uint16, err error) {
	var ws winsize
	err = ioctl(f.Fd(), syscall.TIOCGWINSZ, uintptr(unsafe.Pointer(&ws)))
	return ws.Cols, ws.Rows, err
}

func ioctl(fd, req, arg uintptr) error {
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd, req, arg); errno != 0 {
		return errno
	}
	return nil
}
