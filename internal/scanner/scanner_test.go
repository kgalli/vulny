package scanner_test

import (
	"io/ioutil"
	"os"
	"testing"

	"github.com/kgalli/vulny/internal/scanner"
	"github.com/stretchr/testify/assert"
)

type ScanEngineMock struct{}

func (s *ScanEngineMock) ConstructCmd(image string) (string, string, []string) {
	file, _ := ioutil.TempFile(os.TempDir(), image)
	file.Close()

	return file.Name(), "ls", []string{"-al"}
}

func (s *ScanEngineMock) ParseFindings(input []byte) ([]scanner.Finding, error) {
	findings := []scanner.Finding{
		{Library: "libc6", VulnerabilityID: "CVE-2021-38604"},
	}

	return findings, nil
}

func TestScan(t *testing.T) {
	t.Run("successful scan", func(t *testing.T) {
		expectedFinding := scanner.Finding{
			Library:         "libc6",
			VulnerabilityID: "CVE-2021-38604",
		}
		engine := &ScanEngineMock{}
		subject := scanner.New(engine)

		findings, err := subject.Scan("ubuntu:20.04")

		assert.NoError(t, err)
		assert.Len(t, findings, 1)
		assert.Equal(t, expectedFinding, findings[0])
	})

	t.Run("empty image argument", func(t *testing.T) {
		engine := &ScanEngineMock{}
		subject := scanner.New(engine)

		_, err := subject.Scan("")

		assert.Error(t, err)
	})
}
