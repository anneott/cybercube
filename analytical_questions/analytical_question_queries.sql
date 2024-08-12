---------------------------------------------------------------------------------------------
-- 1. Severity Distribution
---------------------------------------------------------------------------------------------

-- only include cve before 2024-05-01
-- only use version 2 if there is no version 3 present
with version2_metrics as (
		select base_severity, count(*) from metric_v2 mv
			left join cve c ON mv.cve_id = c.id
		where c.published < '2024-05-01'::timestamp
		  and cve_id not in (select cve_id from metric_v3 mvd)
		group by base_severity
	),
	version3_metrics as (
    	select base_severity, count(*) from metric_v3_data mvd
    		left join metric_v3 mv on mv.id = mvd.metric_v3_id
			left join cve c ON c.id = mv.cve_id
		where published < '2024-05-01'::timestamp
		group by base_severity
    )
    select
	    COALESCE(v2.base_severity, v3.base_severity) AS base_severity,
	    COALESCE(v2.count, 0) + COALESCE(v3.count, 0) AS severity_count
	from
	    version2_metrics v2
	full outer join
	    version3_metrics v3
	on
	    v2.base_severity = v3.base_severity
   order by severity_count desc;

---------------------------------------------------------------------------------------------
-- 4. Worst Products and Platforms
---------------------------------------------------------------------------------------------
	with vendors_per_vulnerability as (
		select distinct configuration_node_id, (string_to_array(criteria, ':'))[4] AS vendor
		from configuration_nodes_cpe_match cncm
			left join configuration_nodes cn on cn.id = cncm.configuration_node_id
		    left join configuration c on c.id = cn.configuration_id
		    left join cve on cve.id = c.cve_id
		where vulnerable is true
		  and cve.published < '2024-05-01'::timestamp
		)
	select vendor, count(*) as vulnerability_count
	from vendors_per_vulnerability
	group by vendor
	order by vulnerability_count desc
    limit 10;


	with products_per_vulnerability as (
		select distinct configuration_node_id, (string_to_array(criteria, ':'))[5] AS product
		from configuration_nodes_cpe_match cncm
			left join configuration_nodes cn on cn.id = cncm.configuration_node_id
		    left join configuration c on c.id = cn.configuration_id
		    left join cve on cve.id = c.cve_id
		where vulnerable is true
		  and cve.published < '2024-05-01'::timestamp
		)
	select product, count(*) as vulnerability_count
	from products_per_vulnerability
	group by product
	order by vulnerability_count desc
    limit 10;


---------------------------------------------------------------------------------------------
-- 5. Attack vectors
---------------------------------------------------------------------------------------------

-- filter out all v2 id that are not present in v3 and should be used for analysis
with metric_v2_not_in_v3 as (
	select id from metric_v2 mv
	where cve_id not in (select cve_id from metric_v3)
	),
-- only use v2 in case v3 is not present
-- only include cve before 2024-05-01
  metric_v2_data_not_in_v3 as (
	select * from metric_v2_data mvd
    		left join metric_v2 mv on mvd.metric_v2_id  = mv.id
			left join cve c ON mv.cve_id = c.id
		where c.published < '2024-05-01'::timestamp
	      and mvd.metric_v2_id in (select id from metric_v2_not_in_v3)
   ),
-- count all attack vectors for v2
 metric_v2_count as (
	select access_vector as attack_vector, count(*) from metric_v2_data_not_in_v3
	group by access_vector
   ),
-- count all attack vectors for v3
-- only include cve before 2024-05-01
 metric_v3_count as (
    	select attack_vector, count(*) from metric_v3_data mvd
    		left join metric_v3 mv on mvd.metric_v3_id  = mv.id
			left join cve c ON mv.cve_id = c.id
		where published < '2024-05-01'::timestamp
		group by attack_vector
		)
-- calculate sums for each attack vector across v2 and v3
	select
	    COALESCE(v3.attack_vector, v2.attack_vector) AS attack_vector,
	    COALESCE(v3.count, 0) + COALESCE(v2.count, 0) AS attack_vector_count
	from
	    metric_v3_count v3
	full outer join
	    metric_v2_count v2
	on
	    v2.attack_vector = v3.attack_vector
   order by attack_vector_count desc;