# Cloudflare DynDNS container
Using:  
* [go-external-ip by andygeorge](github.com/andygeorge/go-external-ip)  
* [cloudflare-go by cloudflare](github.com/cloudflare/cloudflare-go)  
This is a application / container for dynamically updating a dns record based on the external ip.  
This is configured using environment variables.  
It is build for the Cloudflare API.  

### Download
Docker image can be fetched from [ghcr.io simonstiil/cfdyndns](https://github.com/SimonStiil/cfdyndns/pkgs/container/cfdyndns)  
Can be build with go build .  
Will also be available as a release in releases in the future

## Setup container with Environment variables
| Option | Description |
| ------ | ----------- |
| CLOUDFLARE_TOKEN | Access token for Cloudflare Account |
| CLOUDFLARE_ZONE | Zone id to use for DNS configuration |
| DYNDNS_NAME | full DNS name of record to på used |
| PROMETHEUS_ENABLED | Enable Prometheus endpoint on /metrics |
| TESTING_ENABLED | Enable testing endpoint on /test (sets new random ip to update to next time) |

## HTTP Endpoints
| endpoint | Description |
| ------ | ----------- |
| /metrics | metrics endpoint for prometheus |
| /health | health endpoint for self and backend services |
| /test | testing endpoint. Sets a random ip to update to |