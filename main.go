package main

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const (
	bytesToBits = 8
	// Maximum number of interfaces to track
	maxInterfaces = 1000
	// Cleanup interval for old interfaces
	cleanupInterval = 5 * time.Minute
)

var (
	networkSpeedBits = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "network_interface_speed_bits",
			Help: "Network interface speed in bits per second",
		},
		[]string{"interface", "direction"},
	)

	networkErrors = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "network_interface_errors_total",
			Help: "Total number of network interface errors",
		},
		[]string{"interface", "direction"},
	)

	networkDrops = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "network_interface_drops_total",
			Help: "Total number of network interface drops",
		},
		[]string{"interface", "direction"},
	)

	networkPackets = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "network_interface_packets_total",
			Help: "Total number of network interface packets",
		},
		[]string{"interface", "direction"},
	)

	// Store previous values for speed calculation with mutex for thread safety
	prevStats = struct {
		sync.RWMutex
		stats map[string]struct {
			rxBytes, txBytes     uint64
			rxPackets, txPackets uint64
			rxErrors, txErrors   uint64
			rxDrops, txDrops     uint64
			time                 time.Time
			lastSeen             time.Time
		}
	}{
		stats: make(map[string]struct {
			rxBytes, txBytes     uint64
			rxPackets, txPackets uint64
			rxErrors, txErrors   uint64
			rxDrops, txDrops     uint64
			time                 time.Time
			lastSeen             time.Time
		}),
	}
)

func init() {
	prometheus.MustRegister(networkSpeedBits)
	prometheus.MustRegister(networkErrors)
	prometheus.MustRegister(networkDrops)
	prometheus.MustRegister(networkPackets)
}

// cleanupOldInterfaces removes interfaces that haven't been seen for a while
func cleanupOldInterfaces() {
	prevStats.Lock()
	defer prevStats.Unlock()

	now := time.Now()
	for iface, stats := range prevStats.stats {
		if now.Sub(stats.lastSeen) > cleanupInterval {
			delete(prevStats.stats, iface)
		}
	}

	// Enforce maximum number of interfaces
	if len(prevStats.stats) > maxInterfaces {
		// Remove oldest interfaces until we're under the limit
		interfaces := make([]string, 0, len(prevStats.stats))
		for iface := range prevStats.stats {
			interfaces = append(interfaces, iface)
		}
		sort.Slice(interfaces, func(i, j int) bool {
			return prevStats.stats[interfaces[i]].lastSeen.Before(prevStats.stats[interfaces[j]].lastSeen)
		})
		for i := 0; i < len(interfaces)-maxInterfaces; i++ {
			delete(prevStats.stats, interfaces[i])
		}
	}
}

func collectNetworkSpeeds() {
	// Create a buffer for scanner to prevent memory allocation
	scannerBuf := make([]byte, 0, 64*1024)

	for {
		// Read /proc/net/dev
		file, err := os.Open("/proc/net/dev")
		if err != nil {
			log.Printf("Error opening /proc/net/dev: %v", err)
			time.Sleep(time.Second)
			continue
		}

		scanner := bufio.NewScanner(file)
		scanner.Buffer(scannerBuf, 1024*1024) // Set max token size to 1MB

		// Skip header lines
		scanner.Scan()
		scanner.Scan()

		// Track current interfaces to clean up old ones
		currentInterfaces := make(map[string]bool)

		for scanner.Scan() {
			line := scanner.Text()
			fields := strings.Fields(line)
			if len(fields) < 17 {
				continue
			}

			// Get interface name (remove the colon)
			ifaceName := strings.TrimSuffix(fields[0], ":")
			currentInterfaces[ifaceName] = true

			// Skip loopback and down interfaces
			iface, err := net.InterfaceByName(ifaceName)
			if err != nil || iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
				continue
			}

			// Parse receive and transmit statistics
			var rxBytes, rxPackets, rxErrors, rxDrops uint64
			var txBytes, txPackets, txErrors, txDrops uint64

			fmt.Sscanf(fields[1], "%d", &rxBytes)
			fmt.Sscanf(fields[2], "%d", &rxPackets)
			fmt.Sscanf(fields[3], "%d", &rxErrors)
			fmt.Sscanf(fields[4], "%d", &rxDrops)
			fmt.Sscanf(fields[9], "%d", &txBytes)
			fmt.Sscanf(fields[10], "%d", &txPackets)
			fmt.Sscanf(fields[11], "%d", &txErrors)
			fmt.Sscanf(fields[12], "%d", &txDrops)

			now := time.Now()
			prevStats.RLock()
			prev, exists := prevStats.stats[ifaceName]
			prevStats.RUnlock()

			if exists {
				// Calculate speed in bits per second
				timeDiff := now.Sub(prev.time).Seconds()
				if timeDiff > 0 {
					// Calculate receive speed in bits per second
					rxSpeed := float64(rxBytes-prev.rxBytes) * bytesToBits / timeDiff
					networkSpeedBits.With(prometheus.Labels{
						"interface": ifaceName,
						"direction": "receive",
					}).Set(rxSpeed)

					// Calculate transmit speed in bits per second
					txSpeed := float64(txBytes-prev.txBytes) * bytesToBits / timeDiff
					networkSpeedBits.With(prometheus.Labels{
						"interface": ifaceName,
						"direction": "transmit",
					}).Set(txSpeed)

					// Set error counters
					networkErrors.With(prometheus.Labels{
						"interface": ifaceName,
						"direction": "receive",
					}).Set(float64(rxErrors))
					networkErrors.With(prometheus.Labels{
						"interface": ifaceName,
						"direction": "transmit",
					}).Set(float64(txErrors))

					// Set drop counters
					networkDrops.With(prometheus.Labels{
						"interface": ifaceName,
						"direction": "receive",
					}).Set(float64(rxDrops))
					networkDrops.With(prometheus.Labels{
						"interface": ifaceName,
						"direction": "transmit",
					}).Set(float64(txDrops))

					// Set packet counters
					networkPackets.With(prometheus.Labels{
						"interface": ifaceName,
						"direction": "receive",
					}).Set(float64(rxPackets))
					networkPackets.With(prometheus.Labels{
						"interface": ifaceName,
						"direction": "transmit",
					}).Set(float64(txPackets))
				}
			}

			// Update previous values
			prevStats.Lock()
			prevStats.stats[ifaceName] = struct {
				rxBytes, txBytes     uint64
				rxPackets, txPackets uint64
				rxErrors, txErrors   uint64
				rxDrops, txDrops     uint64
				time                 time.Time
				lastSeen             time.Time
			}{
				rxBytes:   rxBytes,
				txBytes:   txBytes,
				rxPackets: rxPackets,
				txPackets: txPackets,
				rxErrors:  rxErrors,
				txErrors:  txErrors,
				rxDrops:   rxDrops,
				txDrops:   txDrops,
				time:      now,
				lastSeen:  now,
			}
			prevStats.Unlock()
		}
		file.Close()

		// Clean up old interfaces
		cleanupOldInterfaces()

		time.Sleep(time.Second)
	}
}

func main() {
	// Start collecting network speeds in a goroutine
	go collectNetworkSpeeds()

	// Expose the registered metrics via HTTP
	http.Handle("/metrics", promhttp.Handler())

	log.Println("Starting server on :8080")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatal(err)
	}
}
