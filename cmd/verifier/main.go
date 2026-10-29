package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strings"
	"time"

	"github.com/verirelay/verifier/internal/cli"
	"github.com/verirelay/verifier/internal/webui"
	"github.com/verirelay/verifier/pkg/verifier"
)

var version = "dev"

func main() { os.Exit(run(os.Args[1:])) }
func run(args []string) int {
	if len(args) > 0 {
		switch args[0] {
		case "-h", "--help", "help":
			fmt.Print(cli.Help)
			return 0
		case "version":
			fmt.Println("Verifier " + version)
			return 0
		case "check":
			return cli.Check(context.Background(), args[1:], os.Stdout, os.Stderr, verifier.Options{})
		}
		if !strings.HasPrefix(args[0], "-") {
			fmt.Fprintln(os.Stderr, "Unknown command. Use verifier -h.")
			return 2
		}
	}
	options, err := cli.Web(args, os.Stderr, verifier.Options{})
	if errors.Is(err, flag.ErrHelp) {
		fmt.Print(cli.Help)
		return 0
	}
	if err != nil {
		return 2
	}
	return serve(options)
}

func serve(options verifier.Options) int {
	listener, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	defer func() { _ = listener.Close() }()
	token, err := webui.Token()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	host := listener.Addr().String()
	address := "http://" + host + "/" + token + "/"
	server := webui.Server(webui.Handler(token, host, options))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
	}()
	fmt.Println("Verifier: " + address)
	if err := openBrowser(address); err != nil {
		fmt.Println("Open the URL above in your browser.")
	}
	if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	return 0
}

func openBrowser(address string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var command *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		command = exec.CommandContext(ctx, "open", address) // #nosec G204 -- URL comes only from our loopback listener and random token; no shell or user input.
	case "windows":
		command = exec.CommandContext(ctx, "rundll32", "url.dll,FileProtocolHandler", address) // #nosec G204 -- URL comes only from our loopback listener and random token; no shell or user input.
	default:
		command = exec.CommandContext(ctx, "xdg-open", address) // #nosec G204 -- URL comes only from our loopback listener and random token; no shell or user input.
	}
	return command.Run()
}
