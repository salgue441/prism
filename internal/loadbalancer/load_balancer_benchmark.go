package loadbalancer

import (
	"fmt"
	"testing"
)

func BenchmarkPool_RoundRobin(b *testing.B) {
	pool := NewPool(RoundRobin)
	for i := range 10 {
		backend, _ := NewBackend(fmt.Sprintf("http://localhost:%d", 8000+i), 1)
		pool.AddBackend(backend)
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, err := pool.GetNextBackend("127.0.0.1")
			if err != nil {
				b.Error(err)
			}
		}
	})
}

func BenchmarkPool_WeightedRoundRobin(b *testing.B) {
	pool := NewPool(WeightedRound)
	weights := []int{1, 2, 3, 4, 5}
	for i, weight := range weights {
		backend, _ := NewBackend(fmt.Sprintf("http://localhost:%d", 8000+i), weight)
		pool.AddBackend(backend)
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, err := pool.GetNextBackend("127.0.0.1")
			if err != nil {
				b.Error(err)
			}
		}
	})
}

func BenchmarkPool_LeastConnections(b *testing.B) {
	pool := NewPool(LeastConn)
	for i := range 10 {
		backend, _ := NewBackend(fmt.Sprintf("http://localhost:%d", 8000+i), 1)
		pool.AddBackend(backend)
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			backend, err := pool.GetNextBackend("127.0.0.1")
			if err != nil {
				b.Error(err)
				continue
			}

			backend.AddConnection()
			backend.RemoveConnection()
		}
	})
}

func BenchmarkPool_IPHash(b *testing.B) {
	pool := NewPool(IPHash)
	for i := 0; i < 10; i++ {
		backend, _ := NewBackend(fmt.Sprintf("http://localhost:%d", 8000+i), 1)
		pool.AddBackend(backend)
	}

	clientIPs := []string{
		"192.168.1.1", "192.168.1.2", "192.168.1.3", "192.168.1.4", "192.168.1.5",
		"10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5",
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			clientIP := clientIPs[i%len(clientIPs)]
			_, err := pool.GetNextBackend(clientIP)
			if err != nil {
				b.Error(err)
			}

			i++
		}
	})
}
