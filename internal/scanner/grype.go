package scanner

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/google/uuid"
)

const grypeBinary = "grype"

type grypeScan struct {
	Matches []struct {
		Vulnerability struct {
			ID         string   `json:"id"`
			DataSource string   `json:"dataSource"`
			Namespace  string   `json:"namespace"`
			Severity   string   `json:"severity"`
			URLs       []string `json:"urls"`
			Fix        struct {
				Versions []string `json:"versions"`
				State    string   `json:"state"`
			} `json:"fix"`
		} `json:"vulnerability"`
		Artifact struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"artifact"`
	}
}

type Grype struct{}

func (g *Grype) ConstructCmd(image string) (string, string, []string) {
	outputFile := filepath.Join(os.TempDir(), fmt.Sprintf("%s-%s.json", image, uuid.New().String()))
	args := []string{"--output", "json", "--file", outputFile, image}

	return outputFile, grypeBinary, args
}

func (g *Grype) ParseFindings(input []byte) ([]Finding, error) {
	var scan grypeScan
	err := json.Unmarshal(input, &scan)
	if err != nil {
		return nil, fmt.Errorf("failed to parse grype cmd output: %w", err)
	}

	findings := []Finding{}

	for _, match := range scan.Matches {
		finding := Finding{}
		finding.Library = match.Artifact.Name
		finding.InstalledVersion = match.Artifact.Version
		finding.FixedVersions = match.Vulnerability.Fix.Versions
		finding.VulnerabilityID = match.Vulnerability.ID
		finding.Severity = match.Vulnerability.Severity
		finding.Description = ""
		finding.FixAvailable = len(finding.FixedVersions) > 0
		finding.URL = match.Vulnerability.DataSource

		findings = append(findings, finding)
	}

	return findings, nil
}
