package scanner

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

type Finding struct {
	Library          string
	InstalledVersion string
	FixedVersions    []string
	VulnerabilityID  string
	Severity         string
	Description      string
	FixAvailable     bool
	URL              string
}

type Scanner struct {
	engine ScanEngine
}

type ScanEngine interface {
	ConstructCmd(image string) (string, string, []string)
	ParseFindings([]byte) ([]Finding, error)
}

func New(engine ScanEngine) *Scanner {
	return &Scanner{
		engine: engine,
	}
}

func (s *Scanner) Scan(image string) ([]Finding, error) {
	if image == "" {
		return nil, errors.New("missing image arg")
	}

	outputFile, binary, args := s.engine.ConstructCmd(image)
	cmd := exec.Command(binary, args...)
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("failed to execute cmd '%s': %w",
			strings.Join([]string{binary, strings.Join(args, " ")}, " "),
			err)
	}

	data, err := os.ReadFile(outputFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load %s: %w", outputFile, err)
	}

	if err := os.Remove(outputFile); err != nil {
		return nil, err
	}

	return s.engine.ParseFindings(data)
}
