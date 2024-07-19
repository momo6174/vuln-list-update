package anolis

import "encoding/xml"

type OvalDefinitions struct {
	XMLName     xml.Name    `xml:"oval_definitions"`
	Generator   Generator   `xml:"generator"`
	Definitions Definitions `xml:"definitions"`
}
type Generator struct {
	ProductName    string `xml:"product_name"`
	ProductVersion string `xml:"product_version"`
	SchemaVersion  string `xml:"schema_version"`
	Timestamp      string `xml:"timestamp"`
}
type Definitions struct {
	Definition []Definition `xml:"definition"`
}

type Definition struct {
	Class    string   `xml:"class,attr"`
	ID       string   `xml:"id,attr"`
	Version  string   `xml:"version,attr"`
	Metadata Metadata `xml:"metadata"`
	Criteria Criteria `xml:"criteria"`
}
type Criteria struct {
	Operator  string      `xml:"operator,attr"`
	Criterion []Criterion `xml:"criterion"`
	Criterias []Criteria  `xml:"criteria"`
}
type Criterion struct {
	Comment string `xml:"comment,attr"`
	TestRef string `xml:"test_ref,attr"`
}
type Metadata struct {
	Title       string    `xml:"title"`
	Affected    Affected  `xml:"affected"`
	Reference   Reference `xml:"reference"`
	Description string    `xml:"description"`
	Advisory    Advisory  `xml:"advisory"`
}
type Advisory struct {
	Severity     string          `xml:"severity"`
	Rights       string          `xml:"rights"`
	Issued       Issued          `xml:"issued"`
	Updated      Updated         `xml:"updated"`
	CVE          []CVE           `xml:"cve"`
	AffectedCPEs AffectedCPEList `xml:"affected_cpe_list"`
}
type CVE struct {
	CVSS3  string `xml:"cvss3,attr"`
	CWE    string `xml:"cwe,attr"`
	Href   string `xml:"href,attr"`
	Impact string `xml:"impact,attr"`
	Public string `xml:"public,attr"`
}
type AffectedCPEList struct {
	CPE []string `xml:"cpe"`
}

type Issued struct {
	Date string `xml:"date,attr"`
}
type Updated struct {
	Date string `xml:"date,attr"`
}

type Affected struct {
	Family   string `xml:"family,attr"`
	Platform string `xml:"platform"`
}

type Errata struct {
	Document        Document        `json:"document"`
	ProductTree     ProductTree     `json:"product_tree"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
}

type Document struct {
	AggregateSeverity AggregateSeverity `json:"aggregate_severity"`
	Category          string            `json:"category"`
	CsafVersion       string            `json:"csaf_version"`
	Distribution      Distribution      `json:"distribution"`
	Lang              string            `json:"lang"`
	Notes             []Note            `json:"notes"`
	Publisher         Publisher         `json:"publisher"`
	References        []Reference       `json:"references"`
	Title             string            `json:"title"`
	Tracking          Tracking          `json:"tracking"`
}

type AggregateSeverity struct {
	Namespace string `json:"namespace"`
	Text      string `json:"text"`
}

type Distribution struct {
	Text string `json:"text"`
	Tlp  Tlp    `json:"tlp"`
}

type Tlp struct {
	Label string `json:"label"`
	Url   string `json:"url"`
}

type Note struct {
	Category string `json:"category"`
	Text     string `json:"text"`
	Title    string `json:"title"`
}

type Publisher struct {
	Category         string `json:"category"`
	ContactDetails   string `json:"contact_details"`
	IssuingAuthority string `json:"issuing_authority"`
	Name             string `json:"name"`
	Namespace        string `json:"namespace"`
}

type Reference struct {
	RefID  string `xml:"ref_id,attr"`
	RefURL string `xml:"ref_url,attr"`
	Source string `xml:"source,attr"`
}

type Tracking struct {
	CurrentReleaseDate string            `json:"current_release_date"`
	Id                 string            `json:"id"`
	InitialReleaseDate string            `json:"initial_release_date"`
	RevisionHistory    []RevisionHistory `json:"revision_history"`
}

type RevisionHistory struct {
	Date    string `json:"date"`
	Number  string `json:"number"`
	Summary string `json:"summary"`
}

type ProductTree struct {
	Branches      []Branch       `json:"branches"`
	Relationships []Relationship `json:"relationships"`
}

type Branch struct {
	Branches []Branch `json:"branches,omitempty"`
	Category string   `json:"category"`
	Name     string   `json:"name"`
	Product  *Product `json:"product,omitempty"`
}

type Product struct {
	Name                        string                      `json:"name"`
	ProductId                   string                      `json:"product_id"`
	ProductIdentificationHelper ProductIdentificationHelper `json:"product_identification_helper"`
}

type ProductIdentificationHelper struct {
	Cpe string `json:"cpe"`
}

type Relationship struct {
	Category                  string          `json:"category"`
	FullProductName           FullProductName `json:"full_product_name"`
	ProductReference          string          `json:"product_reference"`
	RelatesToProductReference string          `json:"relates_to_product_reference"`
}

type FullProductName struct {
	Name      string `json:"name"`
	ProductId string `json:"product_id"`
}

type Vulnerability struct {
	Cve           string        `json:"cve"`
	Ids           []Id          `json:"ids"`
	Notes         []Note        `json:"notes"`
	ProductStatus ProductStatus `json:"product_status"`
	References    []Reference   `json:"references"`
	Remediations  []Remediation `json:"remediations"`
	Scores        []Score       `json:"scores"`
	Threats       []Threat      `json:"threats"`
	Title         string        `json:"title"`
}

type Id struct {
	SystemName string `json:"system_name"`
	Text       string `json:"text"`
}

type ProductStatus struct {
	Fixed []string `json:"fixed"`
}

type Remediation struct {
	Category   string   `json:"category"`
	Details    string   `json:"details"`
	ProductIds []string `json:"product_ids"`
}

type Score struct {
	CvssV3 CvssV3 `json:"cvss_v3"`
}

type CvssV3 struct {
	AttackComplexity      string   `json:"attackComplexity"`
	AttackVector          string   `json:"attackVector"`
	AvailabilityImpact    string   `json:"availabilityImpact"`
	BaseScore             float64  `json:"baseScore"`
	BaseSeverity          string   `json:"baseSeverity"`
	ConfidentialityImpact string   `json:"confidentialityImpact"`
	IntegrityImpact       string   `json:"integrityImpact"`
	PrivilegesRequired    string   `json:"privilegesRequired"`
	Scope                 string   `json:"scope"`
	UserInteraction       string   `json:"userInteraction"`
	VectorString          string   `json:"vectorString"`
	Version               string   `json:"version"`
	Products              []string `json:"products"`
}

type Threat struct {
	Category string `json:"category"`
	Date     string `json:"date"`
	Details  string `json:"details"`
}
