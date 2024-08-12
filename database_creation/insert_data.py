import psycopg2


class CVEInsertion:

    def __init__(self):

        self.conn = psycopg2.connect(
            dbname="cve",
            user="postgres",
            password="postgres",
            host="localhost",
            port="5432"
        )
        self.cur = self.conn.cursor()

    def insert_metadata(self, data):
        self.cur.execute("""
            INSERT INTO metadata (results_per_page, start_index, total_results, format, query_timestamp)
            VALUES (%s, %s, %s, %s, %s)
            RETURNING id;
        """, (data["resultsPerPage"], data["startIndex"], data["totalResults"], data["format"], data["timestamp"]))
        metadata_id = self.cur.fetchone()[0]

        self.conn.commit()

        # print('Metadata insertion successful')
        return metadata_id

    def insert_cve(self, cve, metadata_id):
        self.cur.execute("""
                        INSERT INTO cve (cve_id, metadata_id, source_identifier, published, last_modified, vuln_status)
                        VALUES (%s, %s, %s, %s, %s, %s)
                        RETURNING id;
                    """, (
            cve["id"], metadata_id, cve["sourceIdentifier"], cve["published"], cve["lastModified"], cve["vulnStatus"]))

        cve_id = self.cur.fetchone()[0]

        self.conn.commit()
        # print('Inserting to table "cve" successful')
        return cve_id

    def insert_description(self, cve, cve_id):

        for description in cve["descriptions"]:
            self.cur.execute("""
                INSERT INTO descriptions (cve_id, lang, value)
                VALUES (%s, %s, %s)
            """, (cve_id, description["lang"], description["value"]))

        # print('Inserting to table "description" successful')
        self.conn.commit()

    def insert_metrics_v2(self, cve, cve_id):

        for metric_v2 in cve["metrics"].get("cvssMetricV2", []):
            cvss_data = metric_v2["cvssData"]
            self.cur.execute("""
                INSERT INTO metric_v2 (cve_id, version, source, type, base_severity, exploitability_score, impact_score, ac_insuf_info, obtain_all_privilege, obtain_user_privilege, obtain_other_privilege, user_interaction_required)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING id
            """, (
                cve_id,
                cvss_data["version"],
                metric_v2["source"],
                metric_v2["type"],
                metric_v2["baseSeverity"],
                metric_v2["exploitabilityScore"],
                metric_v2["impactScore"],
                metric_v2["acInsufInfo"],
                metric_v2["obtainAllPrivilege"],
                metric_v2["obtainUserPrivilege"],
                metric_v2["obtainOtherPrivilege"],
                metric_v2["userInteractionRequired"]
            ))
            metric_v2_id = self.cur.fetchone()[0]

            # Insert data into metric_v2_data table
            self.cur.execute("""
                INSERT INTO metric_v2_data (metric_v2_id, version, vector_string, access_vector, access_complexity, authentication, confidentiality_impact, integrity_impact, availability_impact, base_score)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                metric_v2_id,
                cvss_data["version"],
                cvss_data["vectorString"],
                cvss_data["accessVector"],
                cvss_data["accessComplexity"],
                cvss_data["authentication"],
                cvss_data["confidentialityImpact"],
                cvss_data["integrityImpact"],
                cvss_data["availabilityImpact"],
                cvss_data["baseScore"]
            ))
        self.conn.commit()
        # print('Inserting to table "metric_v2" and "metric_v2_data" successful')

    def insert_metrics_v3(self, cve, cve_id):
        # 3.0 and 3.1
        for metric_v3 in cve["metrics"].get("cvssMetricV30", []):
            cvss_data = metric_v3["cvssData"]
            self.cur.execute("""
                INSERT INTO metric_v3 (cve_id, version, source, type, exploitability_score, impact_score)
                VALUES (%s, %s, %s, %s, %s, %s)
                RETURNING id
            """, (
                cve_id,
                cvss_data["version"],
                metric_v3["source"],
                metric_v3["type"],
                metric_v3["exploitabilityScore"],
                metric_v3["impactScore"]
            ))
            metric_v3_id = self.cur.fetchone()[0]

            self.cur.execute("""
                INSERT INTO metric_v3_data (metric_v3_id, version, vector_string, attack_vector, attack_complexity, privileges_required, user_interaction, scope, confidentiality_impact, integrity_impact, availability_impact, base_score)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                metric_v3_id,
                cvss_data["version"],
                cvss_data["vectorString"],
                cvss_data["attackVector"],
                cvss_data["attackComplexity"],
                cvss_data["privilegesRequired"],
                cvss_data["userInteraction"],
                cvss_data["scope"],
                cvss_data["confidentialityImpact"],
                cvss_data["integrityImpact"],
                cvss_data["availabilityImpact"],
                cvss_data["baseScore"]
            ))

        # metrics table for version 3.1
        for metric_v3 in cve["metrics"].get("cvssMetricV31", []):
            cvss_data = metric_v3["cvssData"]
            self.cur.execute("""
                INSERT INTO metric_v3 (cve_id, version, source, type, exploitability_score, impact_score)
                VALUES (%s, %s, %s, %s, %s, %s)
                RETURNING id
            """, (
                cve_id,
                cvss_data["version"],
                metric_v3["source"],
                metric_v3["type"],
                metric_v3["exploitabilityScore"],
                metric_v3["impactScore"]
            ))
            metric_v3_id = self.cur.fetchone()[0]

            self.cur.execute("""
                INSERT INTO metric_v3_data (metric_v3_id, version, vector_string, attack_vector, attack_complexity, privileges_required, user_interaction, scope, confidentiality_impact, integrity_impact, availability_impact, base_score, base_severity)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                metric_v3_id,
                cvss_data["version"],
                cvss_data["vectorString"],
                cvss_data["attackVector"],
                cvss_data["attackComplexity"],
                cvss_data["privilegesRequired"],
                cvss_data["userInteraction"],
                cvss_data["scope"],
                cvss_data["confidentialityImpact"],
                cvss_data["integrityImpact"],
                cvss_data["availabilityImpact"],
                cvss_data["baseScore"],
                cvss_data["baseSeverity"]
            ))

        self.conn.commit()
        # print('Inserting to table "metric_v3" and "metric_v3_data" successful')

    def insert_weakness(self, cve, cve_id):
        for weakness in cve.get("weaknesses", []):
            self.cur.execute("""
                INSERT INTO weakness (cve_id, source, type)
                VALUES (%s, %s, %s)
                RETURNING id
            """, (cve_id, weakness["source"], weakness["type"]))
            weakness_id = self.cur.fetchone()[0]

            for description in weakness["description"]:
                self.cur.execute("""
                    INSERT INTO weakness_description (weakness_id, lang, value)
                    VALUES (%s, %s, %s)
                """, (weakness_id, description["lang"], description["value"]))

        self.conn.commit()
        # print('Inserting to table "weakness"  successful')

    def insert_configuration(self, cve, cve_id):
        for configuration in cve.get("configurations", []):
            self.cur.execute("""
                INSERT INTO configuration (cve_id)
                VALUES (%s)
                RETURNING id
            """, (cve_id,))
            configuration_id = self.cur.fetchone()[0]

            # Insert data into configuration_nodes table
            for node in configuration["nodes"]:
                self.cur.execute("""
                    INSERT INTO configuration_nodes (configuration_id, operator, negate)
                    VALUES (%s, %s, %s)
                    RETURNING id
                """, (configuration_id, node["operator"], node["negate"]))
                configuration_node_id = self.cur.fetchone()[0]

                for cpe_match in node["cpeMatch"]:
                    self.cur.execute("""
                        INSERT INTO configuration_nodes_cpe_match (configuration_node_id, vulnerable, criteria, match_criteria_id)
                        VALUES (%s, %s, %s, %s)
                    """, (configuration_node_id, cpe_match["vulnerable"], cpe_match["criteria"],
                          cpe_match["matchCriteriaId"]))

        self.conn.commit()
        # print('Inserting to table "configuration", "configuration_nodes", "configuration_nodes_cpe_match" successful')

    def insert_reference(self, cve, cve_id):

        for reference in cve["references"]:
            self.cur.execute("""
                INSERT INTO reference (cve_id, url, source)
                VALUES (%s, %s, %s)
                RETURNING id
            """, (cve_id, reference['url'], reference['source']))
            reference_id = self.cur.fetchone()[0]

            for reference_tag in reference.get("tags", []):
                self.cur.execute("""
                    INSERT INTO reference_tags (reference_id, tag_name)
                    VALUES ( %s, %s)
                """, (reference_id, reference_tag))

        self.conn.commit()
        # print('Inserting to table "reference", "reference_tag" successful')

    def insert_to_database(self, data):
        metadata_id = self.insert_metadata(data)

        vulnerabilities = data["vulnerabilities"]
        for vulnerability in vulnerabilities:
            cve = vulnerability["cve"]
            cve_id = self.insert_cve(cve, metadata_id)

            self.insert_description(cve, cve_id)
            self.insert_metrics_v2(cve, cve_id)
            self.insert_metrics_v3(cve, cve_id)
            self.insert_weakness(cve, cve_id)
            self.insert_configuration(cve, cve_id)
            self.insert_reference(cve, cve_id)

        self.cur.close()
        self.conn.close()
