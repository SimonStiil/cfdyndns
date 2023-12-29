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
	cloudflare "github.com/cloudflare/cloudflare-go"

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
	e.Init(log.Default())
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
			log.Println("@D Doing Update.")
			if testingEnabled {
				log.Println("@D Working with fake ip")
				updated, err = e.IPChangedFake()
			} else {
				updated, err = e.IPChanged()
			}
			if err != nil {
				health.ExternalIP = err.Error()
				continue
			} else {
				health.ExternalIP = "UP"
			}
			if updated {
				log.Println("@D IP Changed, Updating record.")
				err = c.UpdateRecord(e.LatestIP)
				if err != nil {
					health.Cloudflare = err.Error()
					continue
				} else {
					health.Cloudflare = "UP"
				}
			}
			log.Println("@D Update done.")
		}
	}
}
func setNextTime() {
	nextTime = nextTime.Add(1 * time.Minute)
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
	cfTime = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "cfdyndns_cloudflare_time",
		Help: "Time taken for updating cloudflare dns",
	})
	cfCount = promauto.NewCounter(prometheus.CounterOpts{
		Name: "cfdyndns_cloudflare_count",
		Help: "Times updating cloudflare dns",
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
	config         *CloudflareConfig
	zoneIdentifier *cloudflare.ResourceContainer
	api            *cloudflare.API
	searchRecord   cloudflare.ListDNSRecordsParams
	recordID       string
	context        context.Context
	lastBegin      int64
	lastEnd        int64
}

func (c *Cloudflare) GetZoneFromDNS(dns string) error {
	last := strings.LastIndex(dns, ".")
	secondlast := strings.LastIndex(dns[:last-1], ".")
	ZoneName := dns[secondlast+1:]
	log.Printf("@D ZoneName: %v", ZoneName)
	Zones, err := c.api.ListZones(c.context, ZoneName)
	if err != nil {
		return err
	}
	for _, Zone := range Zones {
		fmt.Printf("@D %v: %v\n", Zone.ID, Zone.Name)
	}
	if len(Zones) == 1 {
		c.config.Zone = Zones[0].ID
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
	api, err := cloudflare.NewWithAPIToken(c.config.Token)
	if err != nil {
		return err
	}
	c.api = api
	if len(c.config.DNSName) == 0 {
		return errors.New(fmt.Sprintf("DNS Name to update not defined in \"%s\"", DNS_NAME_ENV))
	}
	if len(c.config.Zone) == 0 {
		var err error
		err = c.GetZoneFromDNS(c.config.DNSName)
		if err != nil {
			return errors.New(fmt.Sprintf("Cloudflare Zone not defined in \"%s\" and unable to get zone from dns name", ZONE_ENV))
		}
	}
	c.zoneIdentifier = cloudflare.ZoneIdentifier(c.config.Zone)
	c.searchRecord = cloudflare.ListDNSRecordsParams{
		Type: "A",
		Name: c.config.DNSName,
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
		log.Println("@D Looking up Record Identifier")
		dnsList, _, err := c.api.ListDNSRecords(c.context, c.zoneIdentifier, c.searchRecord)
		if err != nil {
			log.Printf("@E error in CF ListDNSRecords:  %+v", err)
			return err
		}
		for _, record := range dnsList {
			token := "-"
			if record.Name == c.config.DNSName {
				token = "+"
				c.recordID = record.ID
			}
			log.Printf("@D %s %s %s %s %+v %s \"%s\"\n", token, record.ID, record.Content, record.Name, *record.Proxied, record.Type, record.Comment)
		}
	}
	if c.recordID == "" {
		log.Println("@D No Preexisting record. Creating first Record")
		record, err := c.api.CreateDNSRecord(
			c.context,
			c.zoneIdentifier,
			cloudflare.CreateDNSRecordParams{Content: ip.String(),
				Name:    c.config.DNSName,
				Proxied: BoolPointer(false),
				Type:    "A",
				Comment: COMMENT})
		if err != nil {
			log.Printf("@E error in CF CreateDNSRecordParams: %+v", err)
		}
		c.recordID = record.ID
		log.Printf("@D - %s %s %s %+v %s \"%s\"\n", record.ID, record.Content, record.Name, *record.Proxied, record.Type, record.Comment)
	} else {
		comment := COMMENT
		record, err := c.api.UpdateDNSRecord(
			c.context,
			c.zoneIdentifier,
			cloudflare.UpdateDNSRecordParams{ID: c.recordID,
				Content: ip.String(),
				Name:    c.config.DNSName,
				Proxied: BoolPointer(false),
				Type:    "A",
				Comment: &comment})
		if err != nil {
			log.Printf("@E error in CF UpdateDNSRecord: %+v", err)
		}
		log.Printf("@D - %s %s %s %+v %s \"%s\"\n", record.ID, record.Content, record.Name, *record.Proxied, record.Type, record.Comment)
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
