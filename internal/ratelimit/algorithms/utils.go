package algorithms

import "time"

// Utility functions

func min(a, b float64) float64 {
	if a < b {
		return a
	}

	return b
}

func max(a, b float64) float64 {
	if a > b {
		return a
	}

	return b
}

// Testing utilities

// SimulateTraffic simulates traffic patterns for testing.
func (lb *LeakyBucket) SimulateTraffic(requests []int64,
	intervals []time.Duration) []bool {
	if len(requests) != len(intervals) {
		return nil
	}

	results := make([]bool, len(requests))
	currentTime := time.Now()

	for i, reqCount := range requests {
		if i > 0 {
			currentTime = currentTime.Add(intervals[i-1])
		}
		
		results[i] = lb.AllowNAt(reqCount, currentTime)
	}

	return results
}
