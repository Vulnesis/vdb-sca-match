// Package sarif is the shared SARIF 2.1.0 read/write model used by the Vulnesis
// CLI and by vdb-api. It is deliberately free of any database, S3 or HTTP
// concern: it parses, validates and decomposes SARIF documents into a normalized
// Finding shape, and nothing else.
//
// Both sides run the same Parse/Validate/Decompose. The CLI runs them to give
// the operator a clear, logged report before anything is sent; the server runs
// them again because a client's decomposition is never authoritative.
package sarif

// Log is the top-level SARIF document.
type Log struct {
	Schema  string `json:"$schema,omitempty"`
	Version string `json:"version"`
	Runs    []Run  `json:"runs"`
}

// Run is a single analysis run by a single tool.
type Run struct {
	Tool                     Tool                        `json:"tool"`
	Results                  []Result                    `json:"results"`
	Artifacts                []Artifact                  `json:"artifacts,omitempty"`
	Invocations              []Invocation                `json:"invocations,omitempty"`
	Taxonomies               []ToolComponent             `json:"taxonomies,omitempty"`
	AutomationDetails        *RunAutomationDetails       `json:"automationDetails,omitempty"`
	VersionControlProvenance []VersionControlDetails     `json:"versionControlProvenance,omitempty"`
	OriginalURIBaseIDs       map[string]ArtifactLocation `json:"originalUriBaseIds,omitempty"`
	Properties               PropertyBag                 `json:"properties,omitempty"`
}

// RunAutomationDetails distinguishes multiple runs of the same tool in one
// logical analysis. Trivy stamps "fs"/"config"/"image" here, which is the only
// machine-readable way to tell its three scan modes apart.
type RunAutomationDetails struct {
	Description *Message `json:"description,omitempty"`
	ID          string   `json:"id,omitempty"`
	GUID        string   `json:"guid,omitempty"`
}

// VersionControlDetails records the repository state the run analysed.
type VersionControlDetails struct {
	RepositoryURI string `json:"repositoryUri,omitempty"`
	RevisionID    string `json:"revisionId,omitempty"`
	Branch        string `json:"branch,omitempty"`
}

// Invocation records how the run executed, including capability degradations
// surfaced as tool execution notifications.
type Invocation struct {
	ExecutionSuccessful        bool           `json:"executionSuccessful"`
	ToolExecutionNotifications []Notification `json:"toolExecutionNotifications,omitempty"`
	CommandLine                string         `json:"commandLine,omitempty"`
	StartTimeUTC               string         `json:"startTimeUtc,omitempty"`
	EndTimeUTC                 string         `json:"endTimeUtc,omitempty"`
}

// Notification is a run-level notification ("couldn't verify X because Y") —
// the honest complement to an empty results array.
type Notification struct {
	Level   string  `json:"level,omitempty"` // note | warning | error
	Message Message `json:"message"`
}

// Tool describes the analysis tool: one driver plus any extensions. CodeQL and
// Semgrep both place rules in extensions, so rule lookup must consider them.
type Tool struct {
	Driver     ToolComponent   `json:"driver"`
	Extensions []ToolComponent `json:"extensions,omitempty"`
}

// ToolComponent is the driver, an extension, or a taxonomy (CWE, OWASP).
type ToolComponent struct {
	Name            string                `json:"name"`
	FullName        string                `json:"fullName,omitempty"`
	Version         string                `json:"version,omitempty"`
	SemanticVersion string                `json:"semanticVersion,omitempty"`
	Organization    string                `json:"organization,omitempty"`
	Product         string                `json:"product,omitempty"`
	InformationURI  string                `json:"informationUri,omitempty"`
	GUID            string                `json:"guid,omitempty"`
	Rules           []ReportingDescriptor `json:"rules,omitempty"`
	Taxa            []ReportingDescriptor `json:"taxa,omitempty"`
	Properties      PropertyBag           `json:"properties,omitempty"`
}

// ReportingDescriptor describes a rule (or a taxon).
type ReportingDescriptor struct {
	ID                   string                        `json:"id"`
	Name                 string                        `json:"name,omitempty"`
	ShortDescription     *Message                      `json:"shortDescription,omitempty"`
	FullDescription      *Message                      `json:"fullDescription,omitempty"`
	Help                 *Message                      `json:"help,omitempty"`
	HelpURI              string                        `json:"helpUri,omitempty"`
	DefaultConfiguration *ReportingConfiguration       `json:"defaultConfiguration,omitempty"`
	Relationships        []ReportingDescriptorRelation `json:"relationships,omitempty"`
	Properties           PropertyBag                   `json:"properties,omitempty"`
}

// ReportingConfiguration carries the rule's default level, used as the last
// severity source when a result carries no level of its own.
type ReportingConfiguration struct {
	Enabled    bool        `json:"enabled,omitempty"`
	Level      string      `json:"level,omitempty"`
	Rank       *float64    `json:"rank,omitempty"`
	Properties PropertyBag `json:"properties,omitempty"`
}

// ReportingDescriptorRelation links a rule to a taxon (typically a CWE).
type ReportingDescriptorRelation struct {
	Target ReportingDescriptorReference `json:"target"`
	Kinds  []string                     `json:"kinds,omitempty"`
}

// ReportingDescriptorReference points at a rule or taxon, by id, by index into
// a tool component's rules/taxa, or by guid.
type ReportingDescriptorReference struct {
	ID            string                  `json:"id,omitempty"`
	Index         *int                    `json:"index,omitempty"`
	GUID          string                  `json:"guid,omitempty"`
	ToolComponent *ToolComponentReference `json:"toolComponent,omitempty"`
}

// ToolComponentReference selects the driver (index absent or -1) or one of the
// extensions/taxonomies by index.
type ToolComponentReference struct {
	Name  string `json:"name,omitempty"`
	Index *int   `json:"index,omitempty"`
	GUID  string `json:"guid,omitempty"`
}

// Message is a SARIF message object.
type Message struct {
	Text      string   `json:"text,omitempty"`
	Markdown  string   `json:"markdown,omitempty"`
	ID        string   `json:"id,omitempty"`
	Arguments []string `json:"arguments,omitempty"`
}

// Result is a single finding.
//
// RuleIndex is a pointer on purpose. SARIF's default for an absent ruleIndex is
// -1, so a plain int would make "absent" indistinguishable from "index 0" and
// would silently attribute every unlabelled result to the first rule.
type Result struct {
	RuleID              string                         `json:"ruleId,omitempty"`
	RuleIndex           *int                           `json:"ruleIndex,omitempty"`
	Rule                *ReportingDescriptorReference  `json:"rule,omitempty"`
	Level               string                         `json:"level,omitempty"`
	Kind                string                         `json:"kind,omitempty"`
	Message             Message                        `json:"message"`
	Locations           []Location                     `json:"locations,omitempty"`
	RelatedLocations    []Location                     `json:"relatedLocations,omitempty"`
	Fingerprints        map[string]string              `json:"fingerprints,omitempty"`
	PartialFingerprints map[string]string              `json:"partialFingerprints,omitempty"`
	Suppressions        []Suppression                  `json:"suppressions,omitempty"`
	Taxa                []ReportingDescriptorReference `json:"taxa,omitempty"`
	GUID                string                         `json:"guid,omitempty"`
	CorrelationGUID     string                         `json:"correlationGuid,omitempty"`
	BaselineState       string                         `json:"baselineState,omitempty"`
	Properties          PropertyBag                    `json:"properties,omitempty"`
}

// Suppression records that a result was suppressed, in source or externally.
type Suppression struct {
	Kind          string `json:"kind,omitempty"`  // inSource | external
	State         string `json:"state,omitempty"` // accepted | underReview | rejected
	Justification string `json:"justification,omitempty"`
	GUID          string `json:"guid,omitempty"`
}

// Location describes where a result was found.
type Location struct {
	PhysicalLocation *PhysicalLocation `json:"physicalLocation,omitempty"`
	Message          *Message          `json:"message,omitempty"`
	Properties       PropertyBag       `json:"properties,omitempty"`
}

// PhysicalLocation identifies a file and region.
type PhysicalLocation struct {
	ArtifactLocation *ArtifactLocation `json:"artifactLocation,omitempty"`
	Region           *Region           `json:"region,omitempty"`
	ContextRegion    *Region           `json:"contextRegion,omitempty"`
}

// ArtifactLocation is a URI reference to an artifact, optionally relative to a
// base id declared in Run.OriginalURIBaseIDs.
type ArtifactLocation struct {
	URI       string `json:"uri,omitempty"`
	URIBaseID string `json:"uriBaseId,omitempty"`
	Index     *int   `json:"index,omitempty"`
}

// Region identifies a portion of an artifact.
type Region struct {
	StartLine   int      `json:"startLine,omitempty"`
	StartColumn int      `json:"startColumn,omitempty"`
	EndLine     int      `json:"endLine,omitempty"`
	EndColumn   int      `json:"endColumn,omitempty"`
	Snippet     *Snippet `json:"snippet,omitempty"`
}

// Snippet holds text from the source.
type Snippet struct {
	Text string `json:"text,omitempty"`
}

// Artifact describes an artifact referenced by results.
type Artifact struct {
	Location    *ArtifactLocation `json:"location,omitempty"`
	Length      int               `json:"length,omitempty"`
	MimeType    string            `json:"mimeType,omitempty"`
	Description *Message          `json:"description,omitempty"`
	Properties  PropertyBag       `json:"properties,omitempty"`
}

// PropertyBag is a property bag for extensible metadata.
type PropertyBag map[string]any

// AddExecutionNotifications attaches capability-degradation notes to every run
// in the log as toolExecutionNotifications (level "warning"). A no-op on an
// empty list — a fully-executed run keeps no invocations block.
func (l *Log) AddExecutionNotifications(notes []string) {
	if l == nil || len(notes) == 0 {
		return
	}
	for i := range l.Runs {
		inv := Invocation{ExecutionSuccessful: true}
		for _, n := range notes {
			inv.ToolExecutionNotifications = append(inv.ToolExecutionNotifications, Notification{
				Level: "warning", Message: Message{Text: n},
			})
		}
		l.Runs[i].Invocations = append(l.Runs[i].Invocations, inv)
	}
}
