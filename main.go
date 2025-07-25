package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	externalip "github.com/andygeorge/go-external-ip"
	"github.com/cloudflare/cloudflare-go/v4"
	"github.com/cloudflare/cloudflare-go/v4/dns"
	"github.com/cloudflare/cloudflare-go/v4/option"
	"github.com/cloudflare/cloudflare-go/v4/zones"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const (
	TOKEN_ENV              = "CLOUDFLARE_TOKEN"
	ZONE_ENV               = "CLOUDFLARE_ZONE"
	DNS_NAME_ENV           = "DYNDNS_NAME"
	PROMETHEUS_ENABLED_ENV = "PROMETHEUS_ENABLED"
	TESTING_ENABLED_ENV    = "TESTING_ENABLED"
	COMMENT                = "Auto created record using SimonStiil/cfdyndns"
)

func main() {

	e := new(Extip)
	if testingEnabled {
		e.Init(log.Default())
	} else {
		e.Init(nil)
	}
	c := new(Cloudflare)
	var err error
	err = c.Init()
	if err != nil {
		panic(err)
	}
	log.Println("@I Starting...")
	prometheusEnabledString := os.Getenv(PROMETHEUS_ENABLED_ENV)
	prometheusEnabled = strings.ToLower(prometheusEnabledString) == "true"
	testingEnabledString := os.Getenv(TESTING_ENABLED_ENV)
	testingEnabled = strings.ToLower(testingEnabledString) == "true"

	http.Handle("/health", http.HandlerFunc(HealthActuator))
	if testingEnabled {
		http.Handle("/fake", http.HandlerFunc(GenerateFakeIP))
	}
	var ip net.IP
	if prometheusEnabled {
		log.Println("I Metrics enabled at /metrics")
		http.Handle("/metrics", promhttp.Handler())
	}
	ip, err = e.getIP()
	if err != nil {
		panic(err)
	}
	e.LatestIP = ip
	err = c.UpdateRecord(ip)
	if err != nil {
		panic(err)
	}
	setNextTime()
	go http.ListenAndServe(":8080", nil)
	log.Println("@I Ready.")
	var updated bool
	for {
		if nextTime.Before(time.Now()) {
			setNextTime()
			if testingEnabled {
				log.Println("@D Doing Update.")
			}
			if testingEnabled {
				log.Println("@D Working with fake ip")
				updated, err = e.IPChangedFake()
			} else {
				updated, err = e.IPChanged()
			}
			if err != nil {
				health.ExternalIP = err.Error()
				log.Printf("@E : %+v\n", err)
				extipErrors.Inc()
				continue
			} else {
				health.ExternalIP = "UP"
			}
			if updated {
				log.Println("@I IP Changed, Updating record.")
				err = c.UpdateRecord(e.LatestIP)
				if err != nil {
					health.Cloudflare = err.Error()
					log.Printf("@E : %+v\n", err)
					cfErrors.Inc()
					continue
				} else {
					health.Cloudflare = "UP"
				}
			}
			if testingEnabled {
				log.Println("@D Update done.")
			}
		}
		time.Sleep(time.Minute)
	}
}
func setNextTime() {
	nextTime = nextTime.Add(10 * time.Minute)
}

type Health struct {
	Cloudflare string `json:"cloudflare"`
	ExternalIP string `json:"externalIP"`
}

func HealthActuator(w http.ResponseWriter, r *http.Request) {
	if prometheusEnabled {
		requests.WithLabelValues(r.URL.EscapedPath(), r.Method).Inc()
	}
	w.Header().Set("Content-Type", "application/json")
	if health.Cloudflare != "UP" && health.ExternalIP != "UP" {
		w.WriteHeader(http.StatusBadRequest)
	}
	json.NewEncoder(w).Encode(health)
	return
}

type FakeIPJson struct {
	IP    string `json:"ip"`
	IPOld string `json:"ipOld"`
}

func GenerateFakeIP(w http.ResponseWriter, r *http.Request) {
	if prometheusEnabled {
		requests.WithLabelValues(r.URL.EscapedPath(), r.Method).Inc()
	}
	newFakeIP := net.ParseIP(fmt.Sprintf("%v.%v.%v.%v", rand.Intn(255), rand.Intn(255), rand.Intn(255), rand.Intn(255)))
	obj := FakeIPJson{
		IP:    newFakeIP.String(),
		IPOld: fakeIP.String(),
	}
	fakeIP = newFakeIP
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(obj)
	return
}

var (
	requests = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "http_endpoint_equests_count",
		Help: "The amount of requests to an endpoint",
	}, []string{"endpoint", "method"})
	extipTime = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "cfdyndns_extip_time",
		Help: "Time taken for last get of extip",
	})
	extipCount = promauto.NewCounter(prometheus.CounterOpts{
		Name: "cfdyndns_extip_count",
		Help: "Times getting last external ip",
	})
	extipErrors = promauto.NewCounter(prometheus.CounterOpts{
		Name: "cfdyndns_extip_errors",
		Help: "Times getting errors while getting external ip",
	})
	cfTime = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "cfdyndns_cloudflare_time",
		Help: "Time taken for updating cloudflare dns",
	})
	cfCount = promauto.NewCounter(prometheus.CounterOpts{
		Name: "cfdyndns_cloudflare_count",
		Help: "Times updating cloudflare dns",
	})
	cfErrors = promauto.NewCounter(prometheus.CounterOpts{
		Name: "cfdyndns_cloudflare_errors",
		Help: "Times getting errors while updating cloudflare dns",
	})
	prometheusEnabled = false
	health            = &Health{Cloudflare: "UP", ExternalIP: "UP"}
	testingEnabled    = false
	fakeIP            = net.ParseIP("0.0.0.0")
	nextTime          = time.Now()
)

type CloudflareConfig struct {
	Token   string
	Zone    string
	DNSName string
}
type Cloudflare struct {
	config    *CloudflareConfig
	client    *cloudflare.Client
	recordID  string
	context   context.Context
	lastBegin int64
	lastEnd   int64
}

func (c *Cloudflare) GetZoneFromDNS(dns string) error {
	last := strings.LastIndex(dns, ".")
	secondlast := strings.LastIndex(dns[:last-1], ".")
	ZoneName := dns[secondlast+1:]
	if testingEnabled {
		log.Printf("@D ZoneName: %v", ZoneName)
	}
	//		c.client.Zones.Get(c.context, option.WithZoneName(c.config.DNSName))
	Zones, err := c.client.Zones.List(c.context, zones.ZoneListParams{Name: cloudflare.F(ZoneName)})
	if err != nil {
		fmt.Printf("@E %+v\n", err)
		return err
	}
	if testingEnabled {
		for _, Zone := range Zones.Result {
			fmt.Printf("@D %v: %v\n", Zone.ID, Zone.Name)
		}
	}
	if len(Zones.Result) == 1 {
		c.config.Zone = Zones.Result[0].ID
	}
	return nil
}

func (c *Cloudflare) Init() error {
	c.context = context.Background()
	if c.config == nil {
		c.config = &CloudflareConfig{
			Token:   os.Getenv(TOKEN_ENV),
			Zone:    os.Getenv(ZONE_ENV),
			DNSName: os.Getenv(DNS_NAME_ENV)}
	}
	if len(c.config.Token) == 0 {
		return errors.New(fmt.Sprintf("Cloudflare Token not defined in \"%s\"", TOKEN_ENV))
	}
	client := cloudflare.NewClient(option.WithAPIToken(c.config.Token))
	c.client = client
	if len(c.config.DNSName) == 0 {
		return errors.New(fmt.Sprintf("DNS Name to update not defined in \"%s\"", DNS_NAME_ENV))
	}
	if len(c.config.Zone) == 0 {
		var err error
		err = c.GetZoneFromDNS(c.config.DNSName)
		if err != nil {
			errmessage := errors.New(fmt.Sprintf("Cloudflare Zone not defined in \"%s\" and unable to get zone from dns name", ZONE_ENV))
			return errors.Join(err, errmessage)
		}
	}
	return nil
}

func BoolPointer(b bool) *bool {
	return &b
}
func (c *Cloudflare) updateRecordEnd() {
	c.lastEnd = time.Now().UnixMilli()
	difference := c.lastEnd - c.lastBegin
	cfTime.Set(float64(difference))
	cfCount.Inc()
}

func (c *Cloudflare) UpdateRecord(ip net.IP) error {
	c.lastBegin = time.Now().UnixMilli()
	defer c.updateRecordEnd()
	if c.recordID == "" {
		if testingEnabled {
			log.Println("@D Looking up Record Identifier")
		}
		dnsList, err := c.client.DNS.Records.List(c.context, dns.RecordListParams{
			Type:   cloudflare.F(dns.RecordListParamsTypeA),
			Name:   cloudflare.F(dns.RecordListParamsName{Exact: cloudflare.F(c.config.DNSName)}),
			ZoneID: cloudflare.F(c.config.Zone),
		})
		if err != nil {
			log.Printf("@E error in CF ListDNSRecords:  %+v", err)
			return err
		}
		for _, record := range dnsList.Result {
			token := "-"
			if record.Name == c.config.DNSName {
				token = "+"
				c.recordID = record.ID
			}
			if testingEnabled {
				log.Printf("@D %s %s %s %s %+v %s \"%s\"\n", token, record.ID, record.Content, record.Name, record.Proxied, record.Type, record.Comment)
			}
		}
	}
	record := dns.ARecordParam{
		Name:    cloudflare.F(c.config.DNSName),
		Proxied: cloudflare.Bool(false),
		Type:    cloudflare.F(dns.ARecordTypeA),
		Content: cloudflare.F(ip.String()),
		Comment: cloudflare.F(COMMENT),
	}
	if c.recordID == "" {
		if testingEnabled {
			log.Println("@D No Preexisting record. Creating first Record")
		}
		record, err := c.client.DNS.Records.New(c.context, dns.RecordNewParams{
			ZoneID: cloudflare.F(c.config.Zone),
			Body:   record})
		if err != nil {
			log.Printf("@E error in CF CreateDNSRecordParams: %+v", err)
		}
		c.recordID = record.ID
		if testingEnabled {
			log.Printf("@D - %s %s %s %+v %s \"%s\"\n", record.ID, record.Content, record.Name, record.Proxied, record.Type, record.Comment)
		}
	} else {
		record, err := c.client.DNS.Records.Update(c.context, c.recordID, dns.RecordUpdateParams{
			ZoneID: cloudflare.F(c.config.Zone),
			Body:   record,
		})
		if err != nil {
			log.Printf("@E error in CF UpdateDNSRecord: %+v", err)
		}
		if testingEnabled {
			log.Printf("@D - %s %s %s %+v %s \"%s\"\n", record.ID, record.Content, record.Name, record.Proxied, record.Type, record.Comment)
		}
	}
	return nil
}

type Extip struct {
	LatestIP  net.IP
	consensus *externalip.Consensus
	lastBegin int64
	lastEnd   int64
}

func (ip *Extip) IPChangedFake() (bool, error) {
	ip.lastBegin = time.Now().UnixMilli()
	defer ip.IPChangedEnd()
	if bytes.Compare(ip.LatestIP, fakeIP) != 0 {
		ip.LatestIP = fakeIP
		return true, nil
	}
	return false, nil
}

func (ip *Extip) Init(logger *log.Logger) {
	ip.consensus = externalip.DefaultConsensus(nil, logger)
	ip.consensus.UseIPProtocol(4)
}
func (ip *Extip) getIP() (net.IP, error) {
	return ip.consensus.ExternalIP()
}
func (ip *Extip) IPChangedEnd() {
	ip.lastEnd = time.Now().UnixMilli()
	difference := ip.lastEnd - ip.lastBegin
	extipTime.Set(float64(difference))
	extipCount.Inc()
}
func (ip *Extip) IPChanged() (bool, error) {
	ip.lastBegin = time.Now().UnixMilli()
	defer ip.IPChangedEnd()
	extip, err := ip.consensus.ExternalIP()
	if err != nil {
		return false, err
	}
	if bytes.Compare(ip.LatestIP, extip) != 0 {
		ip.LatestIP = extip
		return true, nil
	}
	return false, nil
}
