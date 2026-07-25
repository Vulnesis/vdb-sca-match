package sarif

// Finding is the normalized, tool-agnostic view of a single SARIF result.
//
// The JSON tags on the first block are byte-identical to the wire shape the
// Vulnetix CLI and vdb-api already exchange, so this type can be embedded in
// the product-specific finding structs on both sides without changing the
// contract. The second block is read-side information the write-only model
// never captured.
type Finding struct {
	RuleID           string   `json:"ruleId"`
	RuleName         string   `json:"ruleName,omitempty"`
	Message          string   `json:"message,omitempty"`
	Severity         string   `json:"severity,omitempty"`
	Level            string   `json:"level,omitempty"`
	SecuritySeverity string   `json:"securitySeverity,omitempty"`
	File             string   `json:"file,omitempty"`
	PackagePurl      string   `json:"packagePurl,omitempty"`
	StartLine        int      `json:"startLine,omitempty"`
	EndLine          int      `json:"endLine,omitempty"`
	Fingerprint      string   `json:"fingerprint,omitempty"`
	CWEs             []int    `json:"cwes,omitempty"`
	Tags             []string `json:"tags,omitempty"`
	SARIFGuid        string   `json:"sarifGuid,omitempty"`

	Description      string `json:"description,omitempty"`
	CodeSnippet      string `json:"codeSnippet,omitempty"`
	SnippetStartLine int    `json:"snippetStartLine,omitempty"`
	SnippetEndLine   int    `json:"snippetEndLine,omitempty"`

	// Read-side additions.
	HelpURI                  string `json:"helpUri,omitempty"`
	Suppressed               bool   `json:"suppressed,omitempty"`
	SuppressionKind          string `json:"suppressionKind,omitempty"`
	SuppressionJustification string `json:"suppressionJustification,omitempty"`
	ToolName                 string `json:"toolName,omitempty"`
	ToolVersion              string `json:"toolVersion,omitempty"`
	ToolVendor               string `json:"toolVendor,omitempty"`
}
