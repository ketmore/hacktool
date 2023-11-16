# hacktool
Scans your homebrew packages for any vulnerabilities listed in the National Vulnerability Databse (CVEs).
Works on all macOS versions. 

# Build
```
go mod tidy
go build -o hacktool
mkdir ~/.hacktool ~/.hacktool/logs
```
(to install: mv hacktool /insert/preffered/path)

# Install pre-compiled binary
1. Download newest release tarball: https://github.com/ketmore/hacktool/releases
2. Extract: ```tar -xf hacktool_RELEASE*.tar.gz```
3. Set install path (I use /usr/local/bin):```INSTALLPATH=/insert/install/path```
4. Install binary:```cp bin/hacktool $INSTALLPATH``` OR ```sudo cp bin/hacktool $INSTALLPATH``` (if chosen install path is root owned)
5. Create logs directory:```mkdir ~/.hacktool ~/.hacktool/logs```
6. Run:```hacktool```

# About
Made with love by ketmore @ Runtek Software <dangeloizquierdo@gmail.com>

Special thanks to:

github.com/go-resty/resty/v2 - for handling api requests

nvd.nist.gov - for CVE data

(NOTE: Vulnerability data is updated independently from hacktool, ensuring access to newest data even when using a deprecated version.)
