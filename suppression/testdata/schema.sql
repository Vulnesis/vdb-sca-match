-- The saas tables the engine reads and writes, in their shape BEFORE
-- 20261217000000_suppression_provenance. The DB test loads this, then applies
-- the real migration from ../saas, so the test also proves the migration runs
-- against the columns production has. Only columns the engine touches, plus
-- the NOT NULL ones, are kept.
DROP TABLE IF EXISTS "SuppressionAudit", "SuppressionApplication", "Suppression", "Triage", "VexAnalysis",
    "OpenVexStatement", "OpenVex", "Link", "Artifact", "IngestionSnapshot", "CliScanEnvironment", "Finding",
    "ScannerRun", "Member" CASCADE;
DROP FUNCTION IF EXISTS suppression_audit_append_only() CASCADE;

CREATE TABLE "Member" (uuid TEXT PRIMARY KEY, "createdAt" BIGINT NOT NULL DEFAULT 0, email TEXT NOT NULL UNIQUE, "orgId" TEXT NOT NULL);

CREATE TABLE "ScannerRun" (uuid TEXT PRIMARY KEY, "createdAt" BIGINT NOT NULL, "orgId" TEXT NOT NULL,
    "repoName" TEXT, "vexArtifactUuid" TEXT);

CREATE TABLE "CliScanEnvironment" (uuid TEXT PRIMARY KEY, "orgId" TEXT NOT NULL, "scannerRunUuid" TEXT NOT NULL UNIQUE,
    "createdAt" BIGINT NOT NULL, "gitBranch" TEXT, "gitCommit" TEXT);

CREATE TABLE "IngestionSnapshot" (uuid TEXT PRIMARY KEY, "createdAt" BIGINT NOT NULL, "orgId" TEXT NOT NULL,
    "scannerRunUuid" TEXT NOT NULL UNIQUE, "toolName" TEXT NOT NULL, suppressed INT NOT NULL DEFAULT 0);

CREATE TABLE "Finding" (uuid TEXT PRIMARY KEY, "findingId" TEXT NOT NULL, "orgId" TEXT NOT NULL, "repoName" TEXT,
    source TEXT NOT NULL, category TEXT NOT NULL, "createdAt" BIGINT NOT NULL, "modifiedAt" BIGINT NOT NULL,
    "detectionTitle" TEXT NOT NULL, purl TEXT, aliases TEXT, "packageName" TEXT NOT NULL, "packageVersion" TEXT,
    "scannerRunUuid" TEXT);

CREATE TABLE "Triage" (uuid TEXT PRIMARY KEY, "artifactUuid" TEXT, "findingUuid" TEXT NOT NULL, "createdAt" BIGINT NOT NULL,
    "triagedAt" BIGINT, "lastObserved" BIGINT NOT NULL, seen BOOLEAN NOT NULL, "analysisState" TEXT NOT NULL,
    "analysisJustification" TEXT, "analysisResponse" TEXT, "analysisDetail" TEXT,
    "triageAutomated" BOOLEAN NOT NULL DEFAULT false, "memberUuid" TEXT);

CREATE TABLE "Artifact" (uuid TEXT PRIMARY KEY, type TEXT NOT NULL, date BIGINT NOT NULL, "bomFormat" TEXT NOT NULL,
    "r2Bucket" TEXT, "r2Key" TEXT, "fileSize" INT, "contentType" TEXT, checksum TEXT, "uploadSource" TEXT,
    "uploadMethod" TEXT, "uploadedAt" BIGINT, "accessCount" INT NOT NULL DEFAULT 0, "uploadedBy" TEXT,
    "customMetadata" TEXT, "scannerRunUuid" TEXT);

CREATE TABLE "Link" (id SERIAL PRIMARY KEY, url TEXT NOT NULL, "contentType" TEXT NOT NULL, "artifactUuid" TEXT);

CREATE TABLE "OpenVex" (uuid TEXT PRIMARY KEY, "orgId" TEXT NOT NULL, context TEXT NOT NULL, "documentId" TEXT NOT NULL,
    author TEXT NOT NULL, "authorRole" TEXT, timestamp BIGINT NOT NULL, "lastUpdated" BIGINT, version INT NOT NULL DEFAULT 1,
    tooling TEXT, "documentJSON" TEXT NOT NULL, "createdAt" BIGINT NOT NULL, "createdByMember" TEXT);

CREATE TABLE "OpenVexStatement" (uuid TEXT PRIMARY KEY, "openVexUuid" TEXT NOT NULL REFERENCES "OpenVex"(uuid),
    "statementId" TEXT, "statementVersion" INT, timestamp BIGINT NOT NULL, "lastUpdated" BIGINT,
    "vulnerabilityId" TEXT NOT NULL, "vulnerabilityName" TEXT NOT NULL, "vulnerabilityDescription" TEXT,
    "vulnerabilityAliases" TEXT, "productsJSON" TEXT NOT NULL, status TEXT NOT NULL, supplier TEXT, "statusNotes" TEXT,
    justification TEXT, "impactStatement" TEXT, "actionStatement" TEXT, "actionStatementTimestamp" BIGINT);

CREATE TABLE "Suppression" (uuid TEXT PRIMARY KEY, "orgId" TEXT NOT NULL, "findingUuid" TEXT REFERENCES "Finding"(uuid),
    "sonarqubeFindingUuid" TEXT, "githubBranchName" TEXT, "githubRepositoryId" INT, "suppressionType" TEXT NOT NULL,
    "ruleId" TEXT, category TEXT, reason TEXT, "createdAt" BIGINT NOT NULL, "createdBy" TEXT REFERENCES "Member"(uuid),
    "reviewDate" BIGINT, "reviewedBy" TEXT, "ignoreDays" INT, "expiresAt" BIGINT, "configFilePath" TEXT,
    "configFileContent" TEXT, "repositoryFullName" TEXT, "branchName" TEXT, "filePath" TEXT, "lineNumber" INT,
    "lineRange" TEXT, "targetValue" TEXT, "codeSnippet" TEXT, origin TEXT, "updatedAt" BIGINT,
    "isActive" BOOLEAN NOT NULL DEFAULT true, "deactivatedAt" BIGINT, "deactivatedBy" TEXT, "deactivatedReason" TEXT);
