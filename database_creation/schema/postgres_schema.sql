
DROP TABLE IF EXISTS "metadata";
CREATE TABLE "metadata" (
  "id" serial PRIMARY KEY,
  "results_per_page" integer,
  "start_index" integer,
  "total_results" integer,
  "format" varchar,
  "query_timestamp" timestamp
);

DROP TABLE IF EXISTS "cve";
CREATE TABLE "cve" (
  "id" serial PRIMARY KEY,
  "cve_id_text" varchar,
  "metadata_id" integer,
  "source_identifier" varchar,
  "published" timestamp,
  "last_modified" timestamp,
  "vuln_status" varchar
);

DROP TABLE IF EXISTS "cve_tags";
CREATE TABLE "cve_tags" (
  "id" serial PRIMARY KEY,
  "cve_id" integer
);

DROP TABLE IF EXISTS "descriptions";
CREATE TABLE "descriptions" (
  "id" serial PRIMARY KEY,
  "cve_id" integer,
  "lang" varchar(2),
  "value" varchar
);

DROP TABLE IF EXISTS "metric_v3";
CREATE TABLE "metric_v3" (
  "id" serial PRIMARY KEY,
  "cve_id" integer,
  "version" varchar,
  "source" varchar,
  "type" varchar,
  "exploitability_score" float,
  "impact_score" float
);

DROP TABLE IF EXISTS "metric_v3_data";
CREATE TABLE "metric_v3_data" (
  "id" serial PRIMARY KEY,
  "metric_v3_id" integer,
  "version" float,
  "vector_string" varchar,
  "attack_vector" varchar,
  "attack_complexity" varchar,
  "privileges_required" varchar,
  "user_interaction" varchar,
  "scope" varchar,
  "confidentiality_impact" varchar,
  "integrity_impact" varchar,
  "availability_impact" varchar,
  "base_score" float,
  "base_severity" varchar
);

DROP TABLE IF EXISTS "metric_v2";
CREATE TABLE "metric_v2" (
  "id" serial PRIMARY KEY,
  "cve_id" integer,
  "version" varchar,
  "source" varchar,
  "type" varchar,
  "base_severity" varchar,
  "exploitability_score" float,
  "impact_score" float,
  "ac_insuf_info" boolean,
  "obtain_all_privilege" boolean,
  "obtain_user_privilege" boolean,
  "obtain_other_privilege" boolean,
  "user_interaction_required" boolean
);

DROP TABLE IF EXISTS "metric_v2_data";
CREATE TABLE "metric_v2_data" (
  "id" serial PRIMARY KEY,
  "metric_v2_id" integer,
  "version" varchar,
  "vector_string" varchar,
  "access_vector" varchar,
  "access_complexity" varchar,
  "authentication" varchar,
  "confidentiality_impact" varchar,
  "integrity_impact" varchar,
  "availability_impact" varchar,
  "base_score" float
);

DROP TABLE IF EXISTS "weakness";
CREATE TABLE "weakness" (
  "id" serial PRIMARY KEY,
  "cve_id" integer,
  "source" varchar,
  "type" varchar
);

DROP TABLE IF EXISTS "weakness_description";
CREATE TABLE "weakness_description" (
  "id" serial PRIMARY KEY,
  "weakness_id" integer,
  "lang" varchar(2),
  "value" varchar
);

DROP TABLE IF EXISTS "configuration";
CREATE TABLE "configuration" (
  "id" serial PRIMARY KEY,
  "cve_id" integer
);

DROP TABLE IF EXISTS "configuration_nodes";
CREATE TABLE "configuration_nodes" (
  "id" serial PRIMARY KEY,
  "configuration_id" integer,
  "operator" varchar,
  "negate" boolean
);

DROP TABLE IF EXISTS "configuration_nodes_cpe_match";
CREATE TABLE "configuration_nodes_cpe_match" (
  "id" serial PRIMARY KEY,
  "configuration_node_id" integer,
  "vulnerable" boolean,
  "criteria" varchar,
  "match_criteria_id" varchar
);

DROP TABLE IF EXISTS "reference";
CREATE TABLE "reference" (
  "id" serial PRIMARY KEY,
  "cve_id" integer,
  "url" varchar,
  "source" varchar
);

DROP TABLE IF EXISTS "reference_tags";
CREATE TABLE "reference_tags" (
  "id" serial PRIMARY KEY,
  "reference_id" integer,
  "tag_name" varchar
);

-- add relations between tables
ALTER TABLE "cve" ADD FOREIGN KEY ("metadata_id") REFERENCES "metadata" ("id");
ALTER TABLE "cve_tags" ADD FOREIGN KEY ("cve_id") REFERENCES "cve" ("id");
ALTER TABLE "descriptions" ADD FOREIGN KEY ("cve_id") REFERENCES "cve" ("id");
ALTER TABLE "metric_v3_data" ADD FOREIGN KEY ("metric_v3_id") REFERENCES "metric_v3" ("id");
ALTER table "metric_v3" ADD FOREIGN KEY ("cve_id") REFERENCES "cve"  ("id");
ALTER TABLE "metric_v2_data" ADD FOREIGN KEY ("metric_v2_id") REFERENCES "metric_v2" ("id");
ALTER TABLE "metric_v2" ADD FOREIGN KEY ("cve_id") REFERENCES "cve" ("id");
ALTER TABLE "weakness" ADD FOREIGN KEY ("cve_id") REFERENCES "cve" ("id");
ALTER TABLE "weakness_description" ADD FOREIGN KEY ("weakness_id") REFERENCES "weakness" ("id");
ALTER TABLE "configuration" ADD FOREIGN KEY ("cve_id") REFERENCES "cve" ("id");
ALTER TABLE "configuration_nodes" ADD FOREIGN KEY ("configuration_id") REFERENCES "configuration" ("id");
ALTER TABLE "configuration_nodes_cpe_match" ADD FOREIGN KEY ("configuration_node_id") REFERENCES "configuration_nodes" ("id");
ALTER TABLE "reference" ADD FOREIGN KEY ("cve_id") REFERENCES "cve" ("id");
ALTER TABLE "reference_tags" ADD FOREIGN KEY ("reference_id") REFERENCES "reference" ("id");

-- indexes for cve_id
CREATE INDEX idx_cve_cve_id_text ON cve (cve_id_text);
CREATE INDEX idx_cve_cve_id ON cve_tags (cve_id);
CREATE INDEX idx_descriptions_cve_id ON descriptions (cve_id);
CREATE INDEX idx_metric_v3_cve_id ON metric_v3 (cve_id);
CREATE INDEX idx_metric_v2_cve_id ON metric_v2 (cve_id);
CREATE INDEX idx_weakness_cve_id ON weakness (cve_id);
CREATE INDEX idx_configuration_cve_id ON configuration (cve_id);
CREATE INDEX idx_reference_cve_id ON reference (cve_id);

-- indexes for additional id columns
CREATE INDEX idx_metric_v3_metric_v3_id ON metric_v3_data (metric_v3_id);
CREATE INDEX idx_metric_v2_metric_v2_id ON metric_v2_data (metric_v2_id);
CREATE INDEX idx_weakness_weakness_id ON weakness_description (weakness_id);
CREATE INDEX idx_configuration_configuration_id ON configuration_nodes (configuration_id);
CREATE INDEX idx_configuration_nodes_configuration_node_id ON configuration_nodes_cpe_match (configuration_node_id);
CREATE INDEX idx_reference_reference_id ON reference_tags (reference_id);
