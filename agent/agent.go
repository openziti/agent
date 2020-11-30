/*
	Copyright NetFoundry, Inc.

	Licensed under the Apache License, Version 2.0 (the "License");
	you may not use this file except in compliance with the License.
	You may obtain a copy of the License at

	https://www.apache.org/licenses/LICENSE-2.0

	Unless required by applicable law or agreed to in writing, software
	distributed under the License is distributed on an "AS IS" BASIS,
	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
	See the License for the specific language governing permissions and
	limitations under the License.
*/

// Package agent provides hooks programs can register to retrieve
// diagnostics data by using the Ziti CLI.
package agent

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"github.com/michaelquigley/pfxlog"
	"github.com/pkg/errors"
	"io"
	"io/ioutil"
	"net"
	"os"
	"os/signal"
	"path"
	"runtime"
	"runtime/debug"
	"runtime/pprof"
	"runtime/trace"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	mu       sync.Mutex
	tmpfile  string
	listener net.Listener

	units = []string{" bytes", "KB", "MB", "GB", "TB", "PB"}

	Magic      = []byte{0x1, 0xB, 0xA, 0xD, 0xE, 0xC, 0xA, 0xF, 0xE, 0xF, 0x0, 0x0, 0xD}
	SockPrefix = "gops-agent"
)

// Options allows configuring the started agent.
type Options struct {
	// Addr is the host:port the agent will be listening at.
	// Optional.
	Addr string

	// ConfigDir is the directory to store the configuration file,
	// PID of the gops process, filename, port as well as content.
	// Optional.
	ConfigDir string

	// ShutdownCleanup automatically cleans up resources if the
	// running process receives an interrupt. Otherwise, users
	// can call Close before shutting down.
	// Optional.
	ShutdownCleanup *bool
}

// Listen starts the gops agent on a host process. Once agent started, users
// can use the advanced gops features. The agent will listen to Interrupt
// signals and exit the process, if you need to perform further work on the
// Interrupt signal use the options parameter to configure the agent
// accordingly.
//
// Note: The agent exposes an endpoint via a TCP connection that can be used by
// any program on the system. Review your security requirements before starting
// the agent.
func Listen(opts Options) error {
	mu.Lock()
	defer mu.Unlock()

	if listener != nil {
		return errors.Errorf("gops: agent already listening at: %v", listener.Addr())
	}

	if opts.ShutdownCleanup == nil || *opts.ShutdownCleanup {
		gracefulShutdown()
	}

	addr := opts.Addr

	network := "tcp"

	if addr == "" {
		network = "unix"
		tmpfile = path.Join(os.TempDir(), fmt.Sprintf("%v.%v.sock", SockPrefix, os.Getpid()))
		if err := os.Remove(tmpfile); err != nil && !os.IsNotExist(err) {
			return err
		}
		addr = tmpfile
	} else {
		parts := strings.SplitN(addr, ":", 2)

		if len(parts) == 2 {
			network = parts[0]
			addr = parts[1]
		}
	}

	var err error
	if listener, err = net.Listen(network, addr); err != nil {
		return err
	}

	if network == "unix" {
		if err := os.Chmod(tmpfile, 0700); err != nil {
			_ = listener.Close()
			return err
		}
	}

	if opts.ConfigDir != "" {
		if err := os.MkdirAll(opts.ConfigDir, os.ModePerm); err != nil {
			return err
		}

		if tcpAddr, ok := listener.Addr().(*net.TCPAddr); ok {
			port := tcpAddr.Port
			tmpfile = fmt.Sprintf("%s/%d", opts.ConfigDir, os.Getpid())
			if err = ioutil.WriteFile(tmpfile, []byte(strconv.Itoa(port)), os.ModePerm); err != nil {
				return err
			}
		}
	}

	go listen()
	return nil
}

func listen() {
	logger := pfxlog.Logger()

	for {
		if conn, err := listener.Accept(); err != nil {
			logger.WithError(err).Error("error accepting gops connection")
			if netErr, ok := err.(net.Error); ok && !netErr.Temporary() {
				break
			}
		} else {
			handleConnection(conn)
		}
	}
}

func handleConnection(conn net.Conn) {
	defer func() { _ = conn.Close() }()

	logger := pfxlog.Logger()

	if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		logger.WithError(err).Error("unable to set read deadline on gops connection")
		return
	}

	buf := make([]byte, len(Magic)+1)

	if _, err := io.ReadFull(conn, buf); err != nil {
		logger.WithError(err).Error("unable to read gops request")
		return
	}

	if !bytes.Equal(Magic, buf[:len(Magic)]) {
		logger.Error("invalid magic number on gops connection", hex.Dump(buf))
		return
	}

	if err := handle(conn, buf[len(buf)-1]); err != nil {
		logger.WithError(err).Error("error while processing gops request")
		_, _ = conn.Write([]byte(err.Error()))
	}
}

func gracefulShutdown() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		// cleanup the socket on shutdown.
		<-c
		Close()
		os.Exit(1)
	}()
}

// Close closes the agent, removing temporary files and closing the TCP listener.
// If no agent is listening, Close does nothing.
func Close() {
	mu.Lock()
	defer mu.Unlock()

	if listener != nil {
		_ = listener.Close()
	}

	if tmpfile != "" {
		_ = os.Remove(tmpfile)
	}
}

func formatBytes(val uint64) string {
	var i int
	var target uint64
	for i = range units {
		target = 1 << uint(10*(i+1))
		if val < target {
			break
		}
	}
	if i > 0 {
		return fmt.Sprintf("%0.2f%s (%d bytes)", float64(val)/(float64(target)/1024), units[i], val)
	}
	return fmt.Sprintf("%d bytes", val)
}

func handle(conn io.ReadWriter, op byte) error {
	switch op {
	case StackTrace:
		return pprof.Lookup("goroutine").WriteTo(conn, 2)
	case GC:
		runtime.GC()
		_, err := conn.Write([]byte("ok"))
		return err
	case MemStats:
		var s runtime.MemStats
		runtime.ReadMemStats(&s)
		_, _ = fmt.Fprintf(conn, "alloc: %v\n", formatBytes(s.Alloc))
		_, _ = fmt.Fprintf(conn, "total-alloc: %v\n", formatBytes(s.TotalAlloc))
		_, _ = fmt.Fprintf(conn, "sys: %v\n", formatBytes(s.Sys))
		_, _ = fmt.Fprintf(conn, "lookups: %v\n", s.Lookups)
		_, _ = fmt.Fprintf(conn, "mallocs: %v\n", s.Mallocs)
		_, _ = fmt.Fprintf(conn, "frees: %v\n", s.Frees)
		_, _ = fmt.Fprintf(conn, "heap-alloc: %v\n", formatBytes(s.HeapAlloc))
		_, _ = fmt.Fprintf(conn, "heap-sys: %v\n", formatBytes(s.HeapSys))
		_, _ = fmt.Fprintf(conn, "heap-idle: %v\n", formatBytes(s.HeapIdle))
		_, _ = fmt.Fprintf(conn, "heap-in-use: %v\n", formatBytes(s.HeapInuse))
		_, _ = fmt.Fprintf(conn, "heap-released: %v\n", formatBytes(s.HeapReleased))
		_, _ = fmt.Fprintf(conn, "heap-objects: %v\n", s.HeapObjects)
		_, _ = fmt.Fprintf(conn, "stack-in-use: %v\n", formatBytes(s.StackInuse))
		_, _ = fmt.Fprintf(conn, "stack-sys: %v\n", formatBytes(s.StackSys))
		_, _ = fmt.Fprintf(conn, "stack-mspan-inuse: %v\n", formatBytes(s.MSpanInuse))
		_, _ = fmt.Fprintf(conn, "stack-mspan-sys: %v\n", formatBytes(s.MSpanSys))
		_, _ = fmt.Fprintf(conn, "stack-mcache-inuse: %v\n", formatBytes(s.MCacheInuse))
		_, _ = fmt.Fprintf(conn, "stack-mcache-sys: %v\n", formatBytes(s.MCacheSys))
		_, _ = fmt.Fprintf(conn, "other-sys: %v\n", formatBytes(s.OtherSys))
		_, _ = fmt.Fprintf(conn, "gc-sys: %v\n", formatBytes(s.GCSys))
		_, _ = fmt.Fprintf(conn, "next-gc: when heap-alloc >= %v\n", formatBytes(s.NextGC))
		lastGC := "-"
		if s.LastGC != 0 {
			lastGC = fmt.Sprint(time.Unix(0, int64(s.LastGC)))
		}
		_, _ = fmt.Fprintf(conn, "last-gc: %v\n", lastGC)
		_, _ = fmt.Fprintf(conn, "gc-pause-total: %v\n", time.Duration(s.PauseTotalNs))
		_, _ = fmt.Fprintf(conn, "gc-pause: %v\n", s.PauseNs[(s.NumGC+255)%256])
		_, _ = fmt.Fprintf(conn, "num-gc: %v\n", s.NumGC)
		_, _ = fmt.Fprintf(conn, "enable-gc: %v\n", s.EnableGC)
		_, _ = fmt.Fprintf(conn, "debug-gc: %v\n", s.DebugGC)
	case Version:
		_, _ = fmt.Fprintf(conn, "%v\n", runtime.Version())
	case HeapProfile:
		_ = pprof.WriteHeapProfile(conn)
	case CPUProfile:
		if err := pprof.StartCPUProfile(conn); err != nil {
			return err
		}
		time.Sleep(30 * time.Second)
		pprof.StopCPUProfile()
	case Stats:
		_, _ = fmt.Fprintf(conn, "goroutines: %v\n", runtime.NumGoroutine())
		_, _ = fmt.Fprintf(conn, "OS threads: %v\n", pprof.Lookup("threadcreate").Count())
		_, _ = fmt.Fprintf(conn, "GOMAXPROCS: %v\n", runtime.GOMAXPROCS(0))
		_, _ = fmt.Fprintf(conn, "num CPU: %v\n", runtime.NumCPU())
	case BinaryDump:
		executable, err := os.Executable()
		if err != nil {
			return err
		}
		f, err := os.Open(executable)
		if err != nil {
			return err
		}
		defer func() { _ = f.Close() }()

		_, err = bufio.NewReader(f).WriteTo(conn)
		return err
	case Trace:
		if err := trace.Start(conn); err != nil {
			return err
		}
		time.Sleep(5 * time.Second)
		trace.Stop()
	case SetGCPercent:
		perc, err := binary.ReadVarint(bufio.NewReader(conn))
		if err != nil {
			return err
		}
		_, _ = fmt.Fprintf(conn, "New GC percent set to %v. Previous value was %v.\n", perc, debug.SetGCPercent(int(perc)))
	}
	return nil
}
