package wireproxy

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"

	"golang.zx2c4.com/wireguard/tun/netstack"
)

// CheckGoogleConnectivity checks Google connectivity using the WireGuard tunnel's network stack
func CheckGoogleConnectivity(tun *netstack.Net, configName string) error {
	// Step 1: Check IP using icanhazip.com
	ip, err := checkIP(tun, configName)
	if err != nil {
		log.Printf("All retries are completed, VPN is not working. Config name: %s", configName)
		os.Exit(1)
	}
	log.Printf("IP connectivity check successful: %s", ip)

	// Step 2: Check Google connectivity with redirect handling
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: tun.DialContext,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Prevent automatic redirect following
			return http.ErrUseLastResponse
		},
	}
	req, err := http.NewRequest("GET", "https://www.google.com/search?q=what+is+my+ip&num=100", nil)
	if err != nil {
		log.Printf("All retries are completed, VPN is not working. Config name: %s", configName)
		os.Exit(1)
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")

	resp, err := client.Do(req)
	if err != nil {
		log.Printf("All retries are completed, VPN is not working. Config name: %s", configName)
		os.Exit(1)
	}
	defer resp.Body.Close()

	// Log the status code directly from the first response
	log.Printf("Google connectivity check returned status %d", resp.StatusCode)

	if resp.StatusCode == 200 {
		log.Println("Google connectivity check successful: Status 200")
		os.Exit(0)
	} else if resp.StatusCode == 302 {
		log.Printf("Google connectivity check returned status %d (redirect), terminating process. Config name: %s\n", resp.StatusCode, configName)
		os.Exit(1)
	} else if resp.StatusCode >= 100 && resp.StatusCode <= 599 {
		log.Printf("Google connectivity check returned status %d, terminating process. Config name: %s\n", resp.StatusCode, configName)
		os.Exit(1)
	} else {
		log.Printf("Unexpected status code: %d, terminating process. Config name: %s\n", resp.StatusCode, configName)
		os.Exit(1)
	}

	return nil
}

// checkIP checks the public IP using the WireGuard tunnel's network stack
func checkIP(tun *netstack.Net, configName string) (string, error) {
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: tun.DialContext,
		},
	}
	resp, err := client.Get("https://icanhazip.com")
	if err != nil {
		return "", fmt.Errorf("Get \"https://icanhazip.com\": %v", err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("ReadAll: %v", err)
	}

	return strings.TrimSpace(string(body)), nil // Trim any extra whitespace
}