package anolis

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"log"
	"net/http"
	"path/filepath"
	"strings"

	"github.com/spf13/afero"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/vuln-list-update/utils"
)

const (
	ovalURL = "https://anas.openanolis.cn/api/data/OVAL/anolis-8.oval.xml"
	retry   = 5
)

type Config struct {
	VulnListDir string
	URL         string
	AppFs       afero.Fs
	Retry       int
}

func NewConfig() Config {
	return Config{
		VulnListDir: utils.VulnListDir(),
		URL:         ovalURL,
		AppFs:       afero.NewOsFs(),
		Retry:       retry,
	}
}

func (c Config) Update() error {
	log.Println("Fetching Anolis OVAL data...")
	res, err := utils.FetchURL(c.URL, "", c.Retry)
	if err != nil {
		return xerrors.Errorf("failed to fetch Anolis OVAL data: %w", err)
	}
	log.Printf("Fetched data: %s", string(res[:500])) // 输出前100个字符

	var oval OvalDefinitions
	if err := xml.Unmarshal(res, &oval); err != nil {
		return xerrors.Errorf("failed to unmarshal Anolis OVAL XML: %w", err)
	}
	log.Printf("Parsed OVAL data, found %d definitions", len(oval.Definitions.Definition))

	refIDMap := make(map[string][]string)
	for _, def := range oval.Definitions.Definition {
		year := strings.Split(def.Metadata.Advisory.Issued.Date, "-")[0]
		refIDMap[year] = append(refIDMap[year], def.Metadata.Reference.RefID)
	}

	for year, refIDs := range refIDMap {
		log.Printf("Updating errata for year %s with %d refIDs", year, len(refIDs))
		if err := c.updateErrata(year, refIDs); err != nil {
			return xerrors.Errorf("failed to update errata for year %s: %w", year, err)
		}
	}

	return nil
}

func (c Config) updateErrata(year string, refIDs []string) error {
	log.Printf("Updating errata for year %s...", year)
	errataList := []Errata{}
	for _, refID := range refIDs {
		log.Printf("Fetching errata for refID %s", refID)
		errata, err := c.fetchErrata(refID)
		if err != nil {
			log.Printf("Error fetching errata for ref-id %s: %v", refID, err)
			continue
		}
		errataList = append(errataList, errata)
	}

	dir := filepath.Join(c.VulnListDir, "anolis", year)
	if err := utils.WriteJSON(c.AppFs, dir, "errata.json", errataList); err != nil {
		return xerrors.Errorf("failed to write errata JSON: %w", err)
	}
	log.Printf("Successfully wrote errata JSON for year %s", year)

	return nil
}
func formatRefID(refID string) string {
	// 将 `refID` 中的 `ANSA` 转换为小写
	refID = strings.ToLower(refID)
	// 将 `:` 替换为 `_`
	refID = strings.ReplaceAll(refID, ":", "_")
	return refID
}

func (c Config) fetchErrata(refID string) (Errata, error) {
	url := fmt.Sprintf("https://anas.openanolis.cn/api/data/CSAF/advisories/%s.json", formatRefID(refID))
	resp, err := http.Get(url)
	if err != nil {
		return Errata{}, fmt.Errorf("error making HTTP request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return Errata{}, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var errata Errata
	if err := json.NewDecoder(resp.Body).Decode(&errata); err != nil {
		return Errata{}, fmt.Errorf("error decoding JSON response: %w", err)
	}
	log.Printf("Fetched errata: %+v", errata)

	return errata, nil
}
