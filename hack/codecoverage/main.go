// Copyright 2021 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
package main

import (
	"bufio"
	"encoding/json"
	"log"
	"os"
	"strconv"
	"strings"
)

func main() {
	thresholdFile := os.Getenv("THRESHOLD_FILE")
	if thresholdFile == "" {
		log.Fatalf("THRESHOLD_FILE environment variable is not set")
	}
	thresholdMap, err := parseCoverageThreshold(thresholdFile)
	if err != nil {
		log.Fatalf("Error parsing threshold file: %v", err)
	}
	coveragePercentage := os.Getenv("COVERAGE_PERCENTAGE")
	if coveragePercentage == "" {
		log.Fatalf("COVERAGE_PERCENTAGE environment variable is not set")
	}
	coveragePercentageFloat, err := strconv.ParseFloat(coveragePercentage, 32)
	if err != nil {
		log.Fatalf("Error parsing coverage percentage: %v", err)
	}
	// read stream from stdin
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "coverage: ") {
			parts := strings.Fields(line)
			if len(parts) < 5 {
				continue
			}
			percentage, err := strconv.ParseFloat(strings.Trim(parts[4], "%"), 32)
			if err != nil {
				log.Fatalf("invalid line: %s", line)
			}
			pack := parts[1]
			if val, ok := thresholdMap[pack]; !ok {
				if float32(int(percentage*100)/100) < float32(int(coveragePercentageFloat*100)/100) {
					log.Fatalf("coverage for %s is below threshold: %f < %f", pack, percentage, coveragePercentageFloat)
				}
			} else {
				if float32(int(percentage*100)/100) < float32(int(val*100)/100) {
					log.Fatalf("coverage for %s is below threshold: %f < %f", pack, percentage, val)
				}
			}
		}
	}

}

// parseCoverageThreshold parses the threshold file and returns a map.
func parseCoverageThreshold(fileName string) (map[string]float64, error) {
	// Here is an example of the threshold file:
	/*
		{
			  "github.com/sigstore/sigstore/pkg/cryptoutils": 71.2,
			  "github.com/sigstore/sigstore/pkg/oauth/internal" :88.7,
			  "github.com/sigstore/sigstore/pkg/oauth/oidc": 0.8,
			  "github.com/sigstore/sigstore/pkg/oauthflow": 36.4,
			  "github.com/sigstore/sigstore/pkg/signature": 66.5,
			  "github.com/sigstore/sigstore/pkg/signature/dsse": 77.1,
			  "github.com/sigstore/sigstore/pkg/signature/kms": 50.0,
			  "github.com/sigstore/sigstore/pkg/signature/kms/aws": 5.1,
			  "github.com/sigstore/sigstore/pkg/signature/kms/azure": 11.3,
			  "github.com/sigstore/sigstore/pkg/signature/kms/fake": 85.3,
			  "github.com/sigstore/sigstore/pkg/signature/kms/gcp": 18.8,
			  "github.com/sigstore/sigstore/pkg/signature/kms/hashivault":3.6,
			  "github.com/sigstore/sigstore/pkg/signature/payload": 43.8,
			  "github.com/sigstore/sigstore/pkg/signature/ssh": 65.3,
			  "github.com/sigstore/sigstore/pkg/tuf": 66.2
			}
	*/
	f, err := os.Open(fileName)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	thresholdMap := make(map[string]float64)
	if err := json.NewDecoder(f).Decode(&thresholdMap); err != nil {
		return nil, err
	}
	return thresholdMap, nil
}
