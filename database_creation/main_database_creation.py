from random import randint
import logging
from time import sleep
from insert_data import CVEInsertion
from query_data import make_request

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


# read documentation if more metrics versions, implement them or make all version into same table (even though cols different)
# in doc there is also severity level 4, but not in data so not implemented in this solution
# cveTags is always empty
# TODO resultsPerPage maximum is 2000, in total there are 259383 results, so need to query the API 259383/2000 ~= 130 times
# using different start indexes

def save_all_cve_data_to_database(results_per_page):
    """
    Query all cve data from API endpoint and save it to our database.
    Amount of data to be queried during one request is regulated using results_per_page
    :return:
    :rtype:
    """
    # start_indices = list(range(0, 260000, RESULTS_PER_PAGE))
    start_indices = list(range(102000, 258000, RESULTS_PER_PAGE))

    for start_index in start_indices:
        try:
            logging.info(f'Querying data from range {start_index} to {start_index + RESULTS_PER_PAGE}')
            response = make_request(start_index, RESULTS_PER_PAGE)
            logging.info('Starting to insert data to database')
            CVEInsertion().insert_to_database(response)
            logging.info('Successfully inserted data to database')
            # not to get blocked by NVD website
            sleep(randint(10, 50))

        except Exception as e:
            logging.error(f'Failed to insert data to database: {e}', exc_info=True)
# Querying data from range 74000 to 76000
# Starting to insert data to database
# Failed to insert data to database: 'userInteractionRequired'
# Querying data from range 76000 to 78000
# Starting to insert data to database
# Failed to insert data to database: 'userInteractionRequired'


if __name__ == '__main__':
    RESULTS_PER_PAGE = 2000
    save_all_cve_data_to_database(RESULTS_PER_PAGE)

#         # three types of metrics
#         # cvssMetricV2
#         # cvssMetricV30
#         # cvssMetricV31
#         # two tables: metric_v3 (version is either "cvssMetricV30" or "cvssMetricV31", metric_v2 (cvssMetricV2)"
