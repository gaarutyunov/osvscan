package osvscan

type Settings struct {
	// Offline enables offline scanning using local database
	Offline bool `mapstructure:"offline"`

	// DownloadDatabases downloads offline databases when in offline mode
	DownloadDatabases bool `mapstructure:"download-databases"`

	// LocalDBPath specifies path for local vulnerability database
	LocalDBPath string `mapstructure:"local-db-path"`

	// IgnoreVulns is a list of vulnerability IDs to ignore
	IgnoreVulns []string `mapstructure:"ignore-vulns"`

	// MinSeverity filters vulnerabilities below this CVSS score (0-10)
	MinSeverity float64 `mapstructure:"min-severity"`
}
