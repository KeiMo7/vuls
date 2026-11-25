package scanner

import (
	"context"
	"fmt"
	"slices"
	"strconv"
	"time"

	"github.com/future-architect/vuls/logging"
	"github.com/future-architect/vuls/models"
	"github.com/future-architect/vuls/scanner/queue"
)

func (s *Scanner) scanWithQueue(scanFn func(osTypeInterface) error) queue.Report {
	hosts := slices.Clone(servers)
	hostByID := make(map[string]osTypeInterface, len(hosts))

	maxAttempts := s.MaxAttempts
	if maxAttempts < 1 {
		maxAttempts = 1
	}
	opts := queue.Options{
		Workers:     s.Workers,
		MaxAttempts: maxAttempts,
		TaskTimeout: time.Duration(s.TaskTimeoutSec) * time.Second,
	}
	q, err := queue.New(opts)
	if err != nil {
		logging.Log.Errorf("Invalid scan queue options, falling back to parallelExec: %+v", err)
		parallelExec(scanFn, s.ScanTimeoutSec)
		return queue.Report{}
	}

	for i, host := range hosts {
		id := strconv.Itoa(i)
		hostByID[id] = host
		info := host.getServerInfo()
		distro := host.getDistro()
		if err := q.Submit(queue.Task{
			ID:      id,
			Name:    info.GetServerName(),
			Family:  distro.Family,
			Release: distro.Release,
		}); err != nil {
			logging.Log.Errorf("Failed to submit %s to scan queue: %+v", info.GetServerName(), err)
		}
	}

	ctx := context.Background()
	cancel := func() {}
	if s.ScanTimeoutSec > 0 {
		ctx, cancel = context.WithTimeout(ctx, time.Duration(s.ScanTimeoutSec)*time.Second)
	}
	defer cancel()

	report, runErr := q.Run(ctx, func(ctx context.Context, task queue.Task) (*models.ScanResult, error) {
		host := hostByID[task.ID]
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if err := scanFn(host); err != nil {
			host.setErrs([]error{err})
			return nil, err
		}
		result := host.convertToModel()
		return &result, nil
	})
	if runErr != nil {
		logging.Log.Errorf("Scan queue stopped: %+v", runErr)
	}

	s.bridgeQueueReport(report, hostByID)
	return report
}

func (s *Scanner) bridgeQueueReport(report queue.Report, hostByID map[string]osTypeInterface) {
	var succeeded []osTypeInterface
	var failed []osTypeInterface

	for _, outcome := range report.Outcomes {
		host := hostByID[outcome.Task.ID]
		if host == nil {
			continue
		}

		switch outcome.State {
		case queue.StateCanceled:
			err := fmt.Errorf("Timed out: %s", host.getServerInfo().GetServerName())
			logging.Log.Errorf("%+v", err)
			host.setErrs([]error{err})
			failed = append(failed, host)
		case queue.StateFailed:
			if len(host.getErrs()) == 0 && outcome.Err != nil {
				host.setErrs([]error{outcome.Err})
			}
			logging.Log.Errorf("Error on %s, err: %+v", host.getServerInfo().GetServerName(), host.getErrs())
			failed = append(failed, host)
		default:
			if errs := host.getErrs(); len(errs) > 0 {
				logging.Log.Errorf("Error on %s, err: %+v", host.getServerInfo().GetServerName(), errs)
				failed = append(failed, host)
				continue
			}
			succeeded = append(succeeded, host)
		}
	}

	errServers = append(errServers, failed...)
	servers = succeeded
}
