package scanner_test

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kgalli/vulny/internal/scanner"
	"github.com/stretchr/testify/assert"
)

func TestGrype_ConstructCmd(t *testing.T) {
	subject := scanner.Grype{}
	image := "ubuntu:20.04"
	outputFile, binary, args := subject.ConstructCmd(image)
	expectedArgs := fmt.Sprintf("--output json --file %s %s", outputFile, image)

	assert.Equal(t, "grype", binary)
	assert.Equal(t, expectedArgs, strings.Join(args, " "))
}

func TestGrype_ParseFindings(t *testing.T) {
	subject := scanner.Grype{}
	testFile := filepath.Join("..", "..", "testdata", "grype-scan-result.json")
	data, _ := os.ReadFile(testFile)
	expectedFinding := scanner.Finding{
		Library:          "login",
		InstalledVersion: "1:4.8.1-1ubuntu5.20.04.1",
		FixedVersions:    []string{},
		VulnerabilityID:  "CVE-2013-4235",
		Severity:         "Low",
		Description:      "",
		FixAvailable:     false,
		URL:              "http://people.ubuntu.com/~ubuntu-security/cve/CVE-2013-4235",
	}

	findings, err := subject.ParseFindings(data)

	assert.NoError(t, err)
	assert.Len(t, findings, 42)
	assert.Equal(t, expectedFinding, findings[0])
}
