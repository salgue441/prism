// Package scheduler provides cron-like job scheduling.
package scheduler

import (
	"sync"
	"time"

	"github.com/robfig/cron/v3"
)

// Job represents a scheduled job.
type Job struct {
	Name     string
	Schedule string
	Func     func()
	EntryID  cron.EntryID
}

// Scheduler manages scheduled jobs.
type Scheduler struct {
	cron *cron.Cron
	jobs map[string]*Job
	mu   sync.RWMutex
}

// New creates a new scheduler.
func New() *Scheduler {
	return &Scheduler{
		cron: cron.New(cron.WithSeconds()),
		jobs: make(map[string]*Job),
	}
}

// AddJob adds a new scheduled job.
func (s *Scheduler) AddJob(name, schedule string, fn func()) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	entryID, err := s.cron.AddFunc(schedule, fn)
	if err != nil {
		return err
	}

	s.jobs[name] = &Job{
		Name:     name,
		Schedule: schedule,
		Func:     fn,
		EntryID:  entryID,
	}

	return nil
}

// RemoveJob removes a scheduled job.
func (s *Scheduler) RemoveJob(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if job, ok := s.jobs[name]; ok {
		s.cron.Remove(job.EntryID)
		delete(s.jobs, name)
	}
}

// Start starts the scheduler.
func (s *Scheduler) Start() {
	s.cron.Start()
}

// Stop stops the scheduler.
func (s *Scheduler) Stop() {
	ctx := s.cron.Stop()
	<-ctx.Done()
}

// GetJobs returns all scheduled jobs.
func (s *Scheduler) GetJobs() []Job {
	s.mu.RLock()
	defer s.mu.RUnlock()

	jobs := make([]Job, 0, len(s.jobs))
	for _, job := range s.jobs {
		jobs = append(jobs, *job)
	}
	return jobs
}

// GetNextRun returns the next scheduled run time for a job.
func (s *Scheduler) GetNextRun(name string) (time.Time, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	job, ok := s.jobs[name]
	if !ok {
		return time.Time{}, false
	}

	entry := s.cron.Entry(job.EntryID)
	return entry.Next, true
}
