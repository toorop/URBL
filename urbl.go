package main

import (
	"errors"
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/boltdb/bolt"
	"github.com/miekg/dns"
)

const bucket = "bl"

var (
	//DB Bolt connector
	DB *bolt.DB
)

func listenAndServe(ip, port, secret string) {
	// Launch server
	server := &dns.Server{Addr: ip + ":" + port, Net: "udp"}
	if secret != "" {
		server.TsigSecret = map[string]string{"urbl.": secret}
	}
	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("Failed to launch server: %s", err.Error())
	}
}

// return formated key (domain_type)
func formatKey(domain string, rtype uint16) (key string, err error) {
	domain = strings.ToLower(domain)
	if _, ok := dns.IsDomainName(domain); !ok {
		return "", errors.New(domain + " is not a valid domain")
	}
	key = domain + "_" + strconv.Itoa(int(rtype))
	return
}

// Returns a Record (dns.RR) from DB
func getRecord(domain string, rtype uint16) (rr dns.RR, err error) {
	var key string
	var value []byte
	if key, err = formatKey(domain, rtype); err != nil {
		return
	}
	err = DB.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(bucket))
		value = b.Get([]byte(key))

		if len(value) == 0 {
			e := errors.New("Record not found, key:  " + key)
			log.Println(e.Error())
			return e
		}
		return nil
	})
	if err == nil {
		rr, err = dns.NewRR(string(value))
	}
	return
}

// delete a record
func deleteRecord(domain string, rtype uint16) (err error) {
	var key string
	if key, err = formatKey(domain, rtype); err != nil {
		return
	}
	err = DB.Update(func(tx *bolt.Tx) error {
		if err = tx.Bucket([]byte(bucket)).Delete([]byte(key)); err != nil {
			return err
		}
		return nil
	})
	return
}

// save record
func saveRecord(rr dns.RR) (err error) {
	var key string
	if key, err = formatKey(rr.Header().Name, rr.Header().Rrtype); err != nil {
		return
	}
	err = DB.Update(func(tx *bolt.Tx) error {
		if err := tx.Bucket([]byte(bucket)).Put([]byte(key), []byte(rr.String())); err != nil {
			return err
		}
		return nil
	})

	return err
}

// update record
func updateRecord(r dns.RR, q *dns.Question) {

	// record to update
	var rr dns.RR
	// IP of record
	var ip net.IP

	header := r.Header()
	if _, ok := dns.IsDomainName(header.Name); ok {
		if header.Class == dns.ClassANY && header.Rdlength == 0 { // Delete record
			deleteRecord(header.Name, header.Rrtype)
		} else { // Add record
			rheader := dns.RR_Header{
				Name:   header.Name,
				Rrtype: header.Rrtype,
				Class:  dns.ClassINET,
				Ttl:    header.Ttl,
			}

			// IPv4 only
			if a, ok := r.(*dns.A); ok {
				rrr, err := getRecord(header.Name, header.Rrtype)
				if err == nil {
					rr = rrr.(*dns.A)
				} else {
					rr = new(dns.A)
				}
				ip = a.A
				rr.(*dns.A).Hdr = rheader
				rr.(*dns.A).A = ip
				saveRecord(rr)
			}
		}
	}
}

// base handler for dns server
func dnsHandler(w dns.ResponseWriter, request *dns.Msg) {
	response := new(dns.Msg)
	response.SetReply(request)
	response.Compress = false

	switch request.Opcode {
	case dns.OpcodeQuery:
		for _, q := range response.Question {
			if readRR, e := getRecord(q.Name, q.Qtype); e == nil {
				rr := readRR.(dns.RR)
				if rr.Header().Name == q.Name {
					response.Answer = append(response.Answer, rr)
				}
			}
		}
	case dns.OpcodeUpdate:
		if request.IsTsig() != nil && w.TsigStatus() == nil {
			for _, question := range request.Question {
				for _, rr := range request.Ns {
					updateRecord(rr, &question)
				}
			}
		} else {
			log.Println("droping update without tsig or with bad sig")
		}
	}

	if request.IsTsig() != nil {
		if w.TsigStatus() == nil {
			response.SetTsig(request.Extra[len(request.Extra)-1].(*dns.TSIG).Hdr.Name, dns.HmacMD5, 300, time.Now().Unix())
		} else {
			log.Println("Status: ", w.TsigStatus().Error())
		}
	}
	w.WriteMsg(response)
}

// Main
func main() {
	var err error

	// IP
	ip := flag.String("ip", "127.0.0.1", "ip to listen to")
	port := flag.String("port", "53", "port to listen to ")
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

	// create bucket if needed
	err = DB.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte(bucket))
		return err
	})
	if err != nil {
		log.Fatalln(err)
	}

	//dns handler
	dns.HandleFunc(".", dnsHandler)

	// launch server
	go listenAndServe(*ip, *port, *tsigSecret)
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
