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

func TestTrivy_ConstructCmd(t *testing.T) {
	subject := scanner.Trivy{}
	image := "ubuntu:20.04"
	outputFile, binary, args := subject.ConstructCmd(image)
	expectedArgs := fmt.Sprintf("--format json --output %s %s", outputFile, image)

	assert.Equal(t, "trivy", binary)
	assert.Equal(t, expectedArgs, strings.Join(args, " "))
}

func TestTrivy_ParseFindings(t *testing.T) {
	subject := scanner.Trivy{}
	testFile := filepath.Join("..", "..", "testdata", "trivy-scan-result.json")
	data, _ := os.ReadFile(testFile)
	expectedFinding := scanner.Finding{
		Library:          "bash",
		InstalledVersion: "5.0-6ubuntu1.1",
		FixedVersions:    []string{},
		VulnerabilityID:  "CVE-2019-18276",
		Severity:         "LOW",
		Description:      "An issue was discovered in disable_priv_mode in shell.c in GNU Bash through 5.0 patch 11. By default, if Bash is run with its effective UID not equal to its real UID, it will drop privileges by setting its effective UID to its real UID. However, it does so incorrectly. On Linux and other systems that support \"saved UID\" functionality, the saved UID is not dropped. An attacker with command execution in the shell can use \"enable -f\" for runtime loading of a new builtin, which can be a shared object that calls setuid() and therefore regains privileges. However, binaries running with an effective UID of 0 are unaffected.",
		FixAvailable:     false,
		URL:              "https://avd.aquasec.com/nvd/cve-2019-18276",
	}

	findings, err := subject.ParseFindings(data)

	assert.NoError(t, err)
	assert.Len(t, findings, 69)
	assert.Equal(t, expectedFinding, findings[0])
}
