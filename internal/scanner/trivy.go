package scanner

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/google/uuid"
)

const trivyBinary = "trivy"

type trivyScan struct {
	Results []struct {
		Vulnerabilities []struct {
			VulnerabilityID  string `json:"VulnerabilityID"`
			PkgName          string `json:"PkgName"`
			InstalledVersion string `json:"InstalledVersion"`
			FixedVersion     string `json:"FixedVersion"`
			URL              string `json:"PrimaryURL"`
			Severity         string `json:"Severity"`
			Title            string `json:"Title"`
			Description      string `json:"Description"`
		} `json:"Vulnerabilities"`
	} `json:"results"`
}

type Trivy struct{}

func (t *Trivy) ConstructCmd(image string) (string, string, []string) {
	outputFile := filepath.Join(os.TempDir(), fmt.Sprintf("%s-%s.json", image, uuid.New().String()))
	args := []string{"--format", "json", "--output", outputFile, image}

	return outputFile, trivyBinary, args
}

func (t *Trivy) ParseFindings(input []byte) ([]Finding, error) {
	var scan trivyScan
	err := json.Unmarshal(input, &scan)
	if err != nil {
		return nil, fmt.Errorf("failed to parse grype cmd output: %w", err)
	}

	findings := []Finding{}

	for _, result := range scan.Results {
		for _, vuln := range result.Vulnerabilities {
			finding := Finding{}
			finding.Library = vuln.PkgName
			finding.InstalledVersion = vuln.InstalledVersion
			finding.FixedVersions = []string{}

			if vuln.FixedVersion != "" {
				finding.FixedVersions = []string{vuln.FixedVersion}
			}

			finding.VulnerabilityID = vuln.VulnerabilityID
			finding.Severity = vuln.Severity
			finding.Description = vuln.Description
			finding.FixAvailable = len(finding.FixedVersions) > 0
			finding.URL = vuln.URL

			findings = append(findings, finding)
		}
	}

	return findings, nil
}
