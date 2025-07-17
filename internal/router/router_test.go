package router

import (
	"log/slog"
	"os"
	"testing"

	"prism/internal/config"
)

func TestRouter_AddRoute(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	router := New(logger)

	route := config.Route{
		ID:     "test-route",
		Path:   "/api/test",
		Method: "GET",
		Target: "http://localhost:3000",
	}

	err := router.AddRoute(route)
	if err != nil {
		t.Errorf("AddRoute() error = %v", err)
	}

	routes := router.GetRoutes()
	if len(routes) != 1 {
		t.Errorf("Expected 1 route, got %d", len(routes))
	}

	if _, exists := routes["test-route"]; !exists {
		t.Error("Route was not added to routes map")
	}
}

func TestRouter_RemoveRoute(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	router := New(logger)

	route := config.Route{
		ID:     "test-route",
		Path:   "/api/test",
		Target: "http://localhost:3000",
	}
	router.AddRoute(route)

	err := router.RemoveRoute("test-route")
	if err != nil {
		t.Errorf("RemoveRoute() error = %v", err)
	}

	routes := router.GetRoutes()
	if len(routes) != 0 {
		t.Errorf("Expected 0 routes, got %d", len(routes))
	}
}

func TestRouter_Stats(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	router := New(logger)

	routes := []config.Route{
		{ID: "get-route", Path: "/api/get",
			Method: "GET", Target: "http://localhost:3000"},
		{ID: "post-route", Path: "/api/post",
			Method: "POST", Target: "http://localhost:3000"},
		{ID: "all-route", Path: "/api/all",
			Method: "", Target: "http://localhost:3000"},
	}

	for _, route := range routes {
		router.AddRoute(route)
	}

	stats := router.Stats()
	if stats.TotalRoutes != 3 {
		t.Errorf("Expected 3 total routes, got %d", stats.TotalRoutes)
	}

	if stats.RoutesByMethod["GET"] != 1 {
		t.Errorf("Expected 1 GET route, got %d", stats.RoutesByMethod["GET"])
	}

	if stats.RoutesByMethod["POST"] != 1 {
		t.Errorf("Expected 1 POST route, got %d", stats.RoutesByMethod["POST"])
	}

	if stats.RoutesByMethod["ALL"] != 1 {
		t.Errorf("Expected 1 ALL route, got %d", stats.RoutesByMethod["ALL"])
	}
}
