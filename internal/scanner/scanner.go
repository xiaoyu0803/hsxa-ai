package scanner

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/hsxa-ai/net-probe/internal/config"
	"github.com/hsxa-ai/net-probe/internal/iputil"
	"github.com/hsxa-ai/net-probe/internal/portutil"
	"github.com/hsxa-ai/net-probe/internal/result"
	"github.com/schollz/progressbar/v3"
	"golang.org/x/sync/semaphore"
)

// Run executes the full scan described by cfg and returns a ScanResult.
func Run(cfg *config.ScanConfig) (*result.ScanResult, error) {
	ips, err := iputil.Expand(cfg.RawIPs)
	if err != nil {
		return nil, fmt.Errorf("IP expansion failed: %w", err)
	}
	ports, err := portutil.Expand(cfg.RawPorts)
	if err != nil {
		return nil, fmt.Errorf("port expansion failed: %w", err)
	}

	// Build the full task list.
	tasks := make([]task, 0, len(ips)*len(ports))
	for _, ip := range ips {
		for _, port := range ports {
			tasks = append(tasks, task{ip: ip, port: port})
		}
	}

	total := len(tasks)
	bar := progressbar.NewOptions(total,
		progressbar.OptionSetDescription("scanning"),
		progressbar.OptionShowCount(),
		progressbar.OptionSetWidth(40),
		progressbar.OptionClearOnFinish(),
	)

	sem := semaphore.NewWeighted(int64(cfg.Concurrency))
	ctx := context.Background()

	var (
		mu        sync.Mutex
		hosts     []*result.HostResult
		openCount int
	)

	start := time.Now()
	var wg sync.WaitGroup

	for _, t := range tasks {
		t := t // capture loop variable
		if err := sem.Acquire(ctx, 1); err != nil {
			break
		}
		wg.Add(1)
		go func() {
			defer sem.Release(1)
			defer wg.Done()
			defer func() { _ = bar.Add(1) }()

			hr := runTask(t, cfg)

			mu.Lock()
			hosts = append(hosts, hr)
			if hr.Open {
				openCount++
			}
			mu.Unlock()
		}()
	}

	wg.Wait()
	_ = bar.Finish()

	elapsed := time.Since(start)

	return &result.ScanResult{
		Hosts:     hosts,
		Total:     total,
		OpenCount: openCount,
		Elapsed:   elapsed.Round(time.Millisecond).String(),
	}, nil
}
