package pdns

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
)

type PDNSSearchResponseItem struct {
	Name       string `json:"name"`
	Type       string `json:"type"`
	Content    string `json:"content"`
	ObjectType string `json:"object_type"`
	Zone       string `json:"zone"`
	Ttl        int    `json:"ttl"`
}

type PDNSAPI struct {
	URL    string
	APIKey string
	client http.Client
}

func (p *PDNSAPI) Search(query string, objectType string) ([]PDNSSearchResponseItem, error) {
	if objectType == "" {
		objectType = "all"
	}
	req, err := p.newRequest("GET", "/api/v1/servers/localhost/search-data", map[string]any{
		"q":           query,
		"object_type": objectType,
		"max":         9999999,
	})
	if err != nil {
		return nil, err
	}

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode == http.StatusNotFound {
		return []PDNSSearchResponseItem{}, nil
	} else if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var items []PDNSSearchResponseItem
	err = decodeResponse(resp, &items)
	if err != nil {
		return nil, err
	}

	return items, nil
}

func (p *PDNSAPI) newRequest(method string, path string, params map[string]any) (*http.Request, error) {
	url := p.URL + path
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		return nil, err
	}

	log.Debugf("requesting %s", url)
	log.Debugf("params: %v", params)

	req.Header.Add("Accept", "application/json")
	req.Header.Add("Content-Type", "application/json")

	q := req.URL.Query()
	for k, v := range params {
		q.Add(k, fmt.Sprintf("%v", v))
	}
	req.URL.RawQuery = q.Encode()
	req.Header.Add("X-API-Key", p.APIKey)
	return req, nil
}

func NewPDNSAPI(url, apiKey string) *PDNSAPI {
	return &PDNSAPI{
		URL:    url,
		APIKey: apiKey,
		client: http.Client{},
	}
}

func decodeResponse(resp *http.Response, v interface{}) error {
	defer resp.Body.Close()
	return json.NewDecoder(resp.Body).Decode(v)
}

func GetPDNSRecords(ctx context.Context, client *PDNSAPI, search []string, objectType string) ([]PDNSSearchResponseItem, error) {
	g, ctx := errgroup.WithContext(ctx)
	recordsChan := make(chan PDNSSearchResponseItem)

	// Start a goroutine for each search term
	for _, term := range search {
		term := term
		if CheckStringOnlyHostname(term) {
			term = "*" + term + "*"
		} else {
			term = term + "*"
		}
		g.Go(func() error {
			log.Infof("searching for term %s", term)
			records, err := client.Search(term, objectType)
			log.Debug("finished request")
			if err != nil {
				return err
			}
			for _, record := range records {
				select {
				case <-ctx.Done():
					return ctx.Err()
				case recordsChan <- record:
					log.Debugf("Adding %v", record)
				}
			}
			log.Debug("added records to channel")
			return nil
		})
	}

	// Start a separate goroutine to close the channel after all search operations complete
	go func() {
		g.Wait()
		close(recordsChan)
	}()

	var combinedRecords []PDNSSearchResponseItem
	for record := range recordsChan {
		combinedRecords = append(combinedRecords, record)
	}

	// Wait for all operations to complete and collect any errors
	if err := g.Wait(); err != nil {
		return nil, err
	}

	return combinedRecords, nil
}

// CheckStringOnlyHostname returns true if the input
// is only ns1 and not ns1.akqui.net or ns1*
func CheckStringOnlyHostname(input string) bool {
	if !strings.Contains(input, "*") &&
		!strings.Contains(input, ".") &&
		!strings.Contains(input, "?") {
		return true
	}
	return false
}

func FilterRecordsOnType(records []PDNSSearchResponseItem, rType string) []PDNSSearchResponseItem {
	log.Debug("filtering records on type: ", rType)
	filtered := []PDNSSearchResponseItem{}
	for _, r := range records {
		if strings.EqualFold(r.Type, rType) {
			log.Debugf("%s fits filter\n", r.Name)
			filtered = append(filtered, r)
		}
	}
	log.Debugf("Filtered to %d records", len(filtered))
	return filtered
}
