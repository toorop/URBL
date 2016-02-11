package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/boltdb/bolt"
	"github.com/miekg/dns"
)

var (
	//DB Bolt connector
	DB *bolt.DB
)

func listenAndServe(ip, secret string) {

	// Launch server
	server := &dns.Server{Addr: ip + ":1053", Net: "udp"}

	if secret != "" {
		server.TsigSecret = map[string]string{"k": secret}
	}

	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("Failed to launch server: %s", err.Error())
	}

}

// base handler for dns server
func dnsHandler(w dns.ResponseWriter, request *dns.Msg) {
	response := new(dns.Msg)
	response.SetReply(request)
	response.Compress = false

	log.Println(request.Question)
	for _, question := range request.Question {
		log.Println(question.Name, question.Qtype)
		log.Println(question.String())

	}
	w.WriteMsg(response)

}

// Main
func main() {
	var err error

	// IP
	ip := flag.String("ip", "127.0.0.1", "ip to listen to")
	tsigSecret := flag.String("secret", "", "")
	boltPath := flag.String("data", "", "path to bolt DB")

	// parse cmd line
	flag.Parse()

	// bolt init
	if *boltPath == "" {
		log.Fatalln("--data is required")
	}
	DB, err = bolt.Open(*boltPath, 0600, nil)
	if err != nil {
		log.Fatalln(err)
	}
	defer DB.Close()

	//dns handler
	dns.HandleFunc(".", dnsHandler)

	// launch server
	go listenAndServe(*ip, *tsigSecret)
	sig := make(chan os.Signal)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
end:
	for {
		select {
		case s := <-sig:
			log.Printf("Signal (%v) received, stopping", s)
			break end
		}
	}
}
