# -----------------------------------------
# Phantom App Connector python file
# -----------------------------------------

import json
import os
from copy import deepcopy
from datetime import datetime, timedelta

# Phantom App imports
import phantom.app as phantom
from phantom.action_result import ActionResult
from phantom.base_connector import BaseConnector

from qintel_helper import search_qwatch
from qintelqwatch_consts import USER_AGENT


class QWatchConnector(BaseConnector):

    def __init__(self):

        # Call the BaseConnectors init first
        super(QWatchConnector, self).__init__()

        self._state = None

        self.remote = None
        self.client_id = None
        self.client_secret = None

    def _handle_test_connectivity(self):

        try:
            res = search_qwatch(None, None, 'ping', **self.client_args)
            self.debug_print('qwatch test connectivity return: ', res)
        except Exception as e:
            self.debug_print('qwatch test connectivity error: ', e)
            self.set_status(phantom.APP_ERROR,
                            'QWatch Connectivity Test Failed ', e)
            return self.get_status()

        return self.set_status_save_progress(phantom.APP_SUCCESS,
                                             'Test Connectivity Successful')

    def _init_handler(self, param, field):

        self.save_progress("In action handler for: {0}"
                           .format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        return param.get(field), action_result

    def _qwatch_query(self, search_term, search_type, query_type, search_args):

        kwargs = deepcopy(self.client_args)
        kwargs.update(search_args)

        try:
            return search_qwatch(
                search_term,
                search_type,
                query_type,
                **kwargs
            )
        except Exception as e:
            self.debug_print('qwatch lookup failed: ', e)
            raise Exception(str(e))

    def _make_qwatch_times(self, params):

        # stored - start time
        start_time = self._state.get('last_poll')
        if start_time:
            start_time = datetime.strptime(start_time, '%Y-%m-%dT%H:%M:%SZ')
            start_time = int(start_time.timestamp())

        # override - start time
        QWATCH_START = os.getenv('QWATCH_START')
        if QWATCH_START:
            start_time = int(QWATCH_START)
            self.debug_print('_make_qwatch_times',
                             f'overriding start_time to {start_time}')

        # initial poll - start time
        if not start_time:
            if not (1 <= self.qwatch_initial_window <= 90):
                raise Exception(
                    'Config Error: QWatch Initial Ingestion Window '
                    'parameter must be between 1 and 90'
                )

            start_time = datetime.utcnow() - \
                         timedelta(days=self.qwatch_initial_window)
            start_time = int(start_time.timestamp())

        end_time = params.get('end_time')
        if not end_time:
            end_time = int(datetime.utcnow().timestamp())
        else:
            end_time = int(end_time / 1000)  # convert from ms

        return start_time, end_time

    def _make_qwatch_params(self, param):
        start_time, end_time = self._make_qwatch_times(param)

        req_params = {
            'date[start]': start_time,
            'date[end]': end_time,
            'meta[total]': True,
            'stats': True
        }

        if param.get('artifact_count'):
            limit = int(param['artifact_count'])
            if limit < 50:
                self.save_progress('Adjusting artifact limit to minimum of 50')
                limit = 50

            if limit > 10000:
                self.save_progress(
                    'Adjusting artifact limit to maximum of 10000')
                limit = 1000

            req_params['limit'] = limit

        return req_params

    def _process_timestamps(self, exposure):

        ret_ts = {}

        # start time
        timestamps = exposure['attributes']['timestamps']
        for ts in timestamps:
            if ts['context'] == 'loaded':
                ret_ts['loaded'] = f'{ts["iso"]}Z'

        # first seen - cred
        timestamps = exposure['meta']['stats']['credential']['timestamps']
        for ts in timestamps:
            if ts['context'] == 'first_seen':
                ret_ts['first_seen'] = f'{ts["iso"]}Z'

        return ret_ts

    def _process_qwatch_exposure(self, exposure):

        return_data = {}

        timestamps = self._process_timestamps(exposure)

        return_data['credential'] = exposure['attributes']['login_name']

        return_data['password'] = None
        if self.plaintext_passwords:
            return_data['password'] = exposure['attributes']['password']

        return_data['source_name'] = exposure['attributes']['source_name']
        return_data['last_seen'] = timestamps.get('loaded')
        return_data['first_seen'] = timestamps.get('first_seen')

        return return_data

    def _set_severity(self, timestamps, cef):

        source_name = cef['exposureSourceName']
        if source_name.lower().startswith('malware'):
            return 'high'

        if timestamps['loaded'] == timestamps['first_seen']:
            return 'high'

        return 'medium'

    def _process_exposures_ingest(self, data):

        total_creds = data['meta']['total']
        self.save_progress(f'Processing {total_creds} exposures')

        if total_creds == 0:
            return

        container = {
            'name': 'Qintel QWatch Alert',
            'description': f'{total_creds} exposed credentials',
            'artifacts': []
        }

        loaded_ts = []

        for exposure in data.get('data', []):
            artifact = {}

            timestamps = self._process_timestamps(exposure)
            loaded_ts.append(timestamps.get('loaded'))

            cef = {}
            cef_types = {}

            cef['exposedCredential'] = exposure['attributes']['login_name']
            cef_types['exposedCredential'] = ['qwatch credential', 'email']

            cef['exposureSourceName'] = exposure['attributes']['source_name']
            cef_types['exposureSourceName'] = ['qwatch source name']

            artifact['start_time'] = timestamps.get('first_seen')
            artifact['end_time'] = timestamps.get('loaded')

            artifact['severity'] = self._set_severity(timestamps, cef)
            artifact['label'] = 'event'
            artifact['name'] = cef['exposedCredential']

            artifact['cef'] = cef
            artifact['cef_types'] = cef_types
            artifact['data'] = exposure

            container['artifacts'].append(artifact)

        status, msg, id_ = self.save_container(container)
        if status == phantom.APP_ERROR:
            raise Exception(f'Container creation failed: {msg}')

        # save poll time
        self._state['last_poll'] = sorted(loaded_ts)[-1]

        self.save_progress(f'Processed {total_creds} exposures')

    def _handle_qwatch_search(self, param):

        search_type = None

        if param.get('email'):
            search_type = 'email'

        if param.get('domain'):
            search_type = 'domain'

        if not search_type:
            raise Exception('action failed: email OR domain required')

        search_term, action_result = self._init_handler(param, search_type)

        search_args = {
            'params': {
                'meta[total]': True,
                'stats': True
            }
        }

        try:
            results = self._qwatch_query(
                search_term,
                search_type,
                'exposures',
                search_args
            )
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, str(e))

        exposures = results.get('data', [])

        if len(exposures) == 0:
            summary = action_result.update_summary({})
            summary['exposure_count'] = 0
            return action_result.set_status(phantom.APP_SUCCESS)

        for r in exposures:
            return_data = self._process_qwatch_exposure(r)
            action_result.add_data(return_data)

        summary = action_result.update_summary({})
        summary['exposure_count'] = len(exposures)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_qwatch_poll(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))

        search_args = {
            'params': self._make_qwatch_params(param)
        }

        try:
            data = self._qwatch_query(None, None, 'exposures', search_args)
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, str(e))

        self._process_exposures_ingest(data)

        return action_result.set_status(phantom.APP_SUCCESS)

    def handle_action(self, param):

        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()
        self.debug_print("action_id", self.get_action_identifier())

        # qwatch ingest
        if action_id == 'on_poll':
            return self._handle_qwatch_poll(param)

        if action_id == 'test_connectivity':
            ret_val = self._handle_test_connectivity()

        elif action_id == 'qwatch_search_exposures':
            ret_val = self._handle_qwatch_search(param)

        return ret_val

    def initialize(self):

        # Load the state in initialize, use it to store data
        # that needs to be accessed across actions
        self._state = self.load_state()

        # get the asset config
        config = self.get_config()

        self.qwatch_initial_window = int(config['qwatch_initial_window'])
        self.plaintext_passwords = config['qwatch_fetch_password']

        self.client_args = {
            'remote': config.get('remote'),
            'client_id': config['client_id'],
            'client_secret': config['client_secret'],
            'user_agent': USER_AGENT,
            'logger': self.debug_print
        }

        return phantom.APP_SUCCESS

    def finalize(self):

        # Save the state, this data is saved across actions and app upgrades
        self.save_state(self._state)
        return phantom.APP_SUCCESS


if __name__ == '__main__':

    import sys

    if (len(sys.argv) < 2):
        print("No test json specified as input")
        sys.exit(0)

    with open(sys.argv[1]) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = QWatchConnector()
        connector.print_progress_message = True
        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    sys.exit(0)
