///Copyright 2023 D'angelo Izaquierdo (ketmore @ Runtek Software)

package main

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"io"
	"os"
	"strings"
	"time"
	"github.com/go-resty/resty/v2"
)

// NvdResponse represents the structure of the response from the NVD API
type NvdResponse struct {
	CVEItems []struct {
		CVE struct {
			CVEDataMeta struct {
				ID string `json:"ID"`
			} `json:"CVE_data_meta"`
			Description struct {
				DescriptionData []struct {
					Value string `json:"value"`
				} `json:"description_data"`
			} `json:"description"`
		} `json:"cve"`
	} `json:"CVE_Items"`
}

// SoftwarePackage represents a software package
type SoftwarePackage struct {
	Name    string
	Version string
}

// Main function outputs data from results function
func main() {
	results()
}

// getInstalledSoftware retrieves a list of installed software packages
func getInstalledSoftware() ([]SoftwarePackage, error) {
	cmd := exec.Command("sh", "-c", "brew list --formula") // Assumes Homebrew is installed
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, err
	}

	// Split the output into lines and create SoftwarePackage objects
	fmt.Printf("Scanned Packages:\n"+string(output))
	lines := strings.Split(string(output), "\n")
	var installedSoftware []SoftwarePackage
	for _, line := range lines {
		// Extract package name and version
		parts := strings.SplitN(line, " ", 2)
		if len(parts) == 2 {
			installedSoftware = append(installedSoftware, SoftwarePackage{Name: parts[0], Version: parts[1]})
		}
	}

	return installedSoftware, nil
}

// checkVulnerabilities checks for vulnerabilities using NVD
func checkVulnerabilities(installedSoftware []SoftwarePackage) ([]SoftwarePackage, error) {
	var vulnerablePackages []SoftwarePackage

	for _, installedPkg := range installedSoftware {
		cveID, err := queryNVD(installedPkg.Name, installedPkg.Version)
		if err != nil {
			return nil, err
		}

		if cveID != "" {
			vulnerablePackages = append(vulnerablePackages, installedPkg)
		}
	}

	return vulnerablePackages, nil
}

// queryNVD queries the NVD API for vulnerabilities
func queryNVD(packageName, packageVersion string) (string, error) {
	// Construct the API URL based on the package name and version
	apiURL := fmt.Sprintf("https://services.nvd.nist.gov/rest/json/cves/2.0?cpeMatchString=cpe:/a:%s:%s", packageName, packageVersion)

	// Make the API request
	resp, err := resty.New().R().Get(apiURL)
	if err != nil {
		return "", err
	}

	// Parse the JSON response
	var nvdResponse NvdResponse
	err = json.Unmarshal(resp.Body(), &nvdResponse)
	if err != nil {
		return "", err
	}

	// Check if any CVEs were found
	if len(nvdResponse.CVEItems) > 0 {
		// Return the first CVE ID found (you might want to handle multiple CVEs differently)
		return nvdResponse.CVEItems[0].CVE.CVEDataMeta.ID, nil
	}

	return "", nil
}

func results(){
	// Get a list of installed software packages
	installedSoftware, err := getInstalledSoftware()
	// Get user home folder
	home, err := os.UserHomeDir()
	// Set working path for logs
	logFolderPath := (home + "/.hacktool/logs/")
	// Get time for logs
	currentTime := time.Now()
	fn := currentTime.Format("2006-1-2_15-4-5")
	// Set format for log files
	logFile := (logFolderPath + fn)
	// Open empty log file
	file, err := os.OpenFile(logFile, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0666)
	// Error handling for logs directory
	if os.IsNotExist(err) {
	    fmt.Println("Error saving logs, please make sure ~/.hacktool/logs exists.")
	}
	// Send Stdout to logCurrent(RAM) and log file(DISK)
	logCurrent := io.MultiWriter(os.Stdout, file)
	if err != nil {
		fmt.Fprintln(logCurrent,"-Error:",currentTime, err)
		return
	}
	// Check for vulnerabilities using NVD
	vulnerablePackages, err := checkVulnerabilities(installedSoftware)
	if err != nil {
		fmt.Fprintln(logCurrent,"-Error checking vulnerabilities:",currentTime, err)
		return
	}
	// Display the results
	if len(vulnerablePackages) > 0 {
		fmt.Fprintln(logCurrent,"-Vulnerable software found:",currentTime)
		for _, pkg := range vulnerablePackages {
			fmt.Printf("%s %s\n", pkg.Name, pkg.Version)
		}
	} else {
		fmt.Fprintln(logCurrent,"\n-No vulnerable software found.\n",currentTime)
	}
}
