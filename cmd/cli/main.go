package main

import (
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/kgalli/vulny/internal/scanner"
)

var Version = ""
var GitHead = ""

func main() {
	args := os.Args[1:]

	if len(args) == 0 {
		log.Fatal("missing image argument")
	}

	engine := &scanner.Grype{}
	grype := scanner.New(engine)

	image := args[0]
	findings, err := grype.Scan(image)
	if err != nil {
		log.Fatal(err)
	}

	for _, finding := range findings {
		fmt.Printf("Library: %s\n", finding.Library)
		fmt.Printf("VulnerabilityID  : %s\n", finding.VulnerabilityID)
		fmt.Printf("InstalledVersion: %s\n", finding.InstalledVersion)
		fmt.Printf("Severity: %s\n", finding.Severity)
		fmt.Printf("FixedVersions: %s\n", strings.Join(finding.FixedVersions, ", "))
		fmt.Printf("FixAvailable: %t\n", finding.FixAvailable)
	}
}
