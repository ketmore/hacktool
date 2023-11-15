# hacktool
Scans your homebrew packages for any vulneribilites listed in the National Vulnerability Databse.
Works on all macOS versions.

# Build
go mod tidy
go build -o hacktool
(to install: mv hacktool /insert/preffered/path)

# Install pre-compiled binary
1. Download newest release
2. Extract
3. Edit install.sh to choose install path
4. ./install.sh OR sudo ./install (if chosen install path is root owned)

Made with love by ketmore @ Runtek Software <dangeloizquierdo@gmail.com>
