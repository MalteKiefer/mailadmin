package cli

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"mailadmin/internal/applemobile"
	"mailadmin/internal/db"
	"mailadmin/internal/install"
)

// newAppleServeCmd runs the Apple profile form. It is started by systemd as an
// unprivileged user. It reads the allow-list file, so it needs no database.
func newAppleServeCmd(app *App) *cobra.Command {
	var listen, host, domainsFile string
	cmd := &cobra.Command{
		Use:    "apple-serve",
		Short:  "Serve the Apple profile form (run by systemd)",
		Hidden: true,
		Args:   cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			if listen == "" || host == "" {
				return fmt.Errorf("%w: --listen and --host are required", ErrUsage)
			}
			if domainsFile == "" {
				domainsFile = install.AppleDomainsPath
			}
			h := applemobile.NewHandler(host, func() (map[string]bool, error) {
				return applemobile.ReadDomainList(domainsFile)
			})
			srv := &http.Server{
				Addr:              listen,
				Handler:           h,
				ReadHeaderTimeout: 5 * time.Second,
				ReadTimeout:       10 * time.Second,
				WriteTimeout:      15 * time.Second,
				IdleTimeout:       30 * time.Second,
				MaxHeaderBytes:    8 << 10,
			}
			stop := make(chan os.Signal, 1)
			signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
			errc := make(chan error, 1)
			go func() { errc <- srv.ListenAndServe() }()
			select {
			case err := <-errc:
				if errors.Is(err, http.ErrServerClosed) {
					return nil
				}
				return err
			case <-stop:
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				return srv.Shutdown(ctx)
			}
		},
	}
	cmd.Flags().StringVar(&listen, "listen", "", "local address to listen on, e.g. 127.0.0.1:8082")
	cmd.Flags().StringVar(&host, "host", "", "mail server host name written into the profile")
	cmd.Flags().StringVar(&domainsFile, "domains-file", "", "allow-list of active mail domains")
	_ = app
	return cmd
}

// activeDomainNames returns the names of the active domains.
func activeDomainNames(domains []db.Domain) []string {
	out := make([]string, 0, len(domains))
	for _, d := range domains {
		if d.Active {
			out = append(out, d.Name)
		}
	}
	return out
}
