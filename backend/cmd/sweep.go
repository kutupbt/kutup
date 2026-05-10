// Package cmd hosts admin-runnable subcommands of the kutup-server binary.
// Today: orphan-sweep. The dispatcher lives in main.go and only triggers if
// os.Args[1] matches a known subcommand; otherwise the normal HTTP server
// starts. Same binary, no new Docker stage.
package cmd

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/kutup/backend/services"
)

// RunOrphanSweep parses the subcommand flags and invokes the sweep. Exit
// code 0 on success, 1 on operational error. Dry-run is the default;
// --delete must be passed explicitly to actually remove orphans.
//
// Usage:
//
//	kutup-server orphan-sweep                        # dry-run, 24h age, 200ms sleep
//	kutup-server orphan-sweep --delete               # actually delete
//	kutup-server orphan-sweep --age-floor=1h         # tighter age window (testing)
//	kutup-server orphan-sweep --page-sleep=0         # no inter-page sleep (testing)
func RunOrphanSweep(pool *pgxpool.Pool, storage *services.StorageService, args []string) int {
	fs := flag.NewFlagSet("orphan-sweep", flag.ContinueOnError)
	doDelete := fs.Bool("delete", false, "actually delete orphan blobs (default: dry-run)")
	ageFloor := fs.Duration("age-floor", 24*time.Hour, "skip blobs younger than this")
	pageSleep := fs.Duration("page-sleep", 200*time.Millisecond, "sleep between S3 LIST pages")
	prefix := fs.String("prefix", "files/", "S3 key prefix to walk")
	fs.SetOutput(os.Stderr)
	if err := fs.Parse(args); err != nil {
		return 1
	}

	mode := "DRY-RUN"
	if *doDelete {
		mode = "DELETE"
	}
	log.Printf("orphan-sweep: starting mode=%s age-floor=%s page-sleep=%s prefix=%s",
		mode, ageFloor.String(), pageSleep.String(), *prefix)

	sweep := &services.OrphanSweep{
		DB:         pool,
		Storage:    storage,
		AgeFloor:   *ageFloor,
		PageSleep:  *pageSleep,
		PrefixRoot: *prefix,
		Delete:     *doDelete,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	res, err := sweep.Run(ctx)
	if res != nil {
		res.LogSummary(!*doDelete)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "orphan-sweep: failed: %v\n", err)
		return 1
	}
	return 0
}
