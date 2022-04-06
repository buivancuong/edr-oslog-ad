from controller.data_input.data_input import DataInput

from elasticsearch import Elasticsearch
import logging
import re

class Elastic(DataInput):
    def __init__(self):
        self.es = Elasticsearch(['http://localhost:8686'])

    def get_systemlog(self):
        query = {
            "query": {
                "bool": {
                    "must": {
                        "regexp": {
                            "SenderAlias": "DESKTOP-PKMLDH5"
                        }
                    },
                    "filter": {
                        "range": {
                            "@timestamp": {
                                "gte": "now-1d"
                            }
                        }
                    }
                }
            },
            "sort":[
                {
                    "@timestamp": {
                        "order":"asc"
                    }
                }
            ]
        }
        try:
            result_log = self.es.search(
                index='os_windows_systemlog',
                body=query,
                request_timeout=30,
                size=10000,
                scroll='10m'
            )
        except Exception as err:
            logging.error("Cannot get data from Elasticsearch")
            logging.error(err)
            logging.exception("ES search")
        with open('sysmon.json', 'w') as f:
            import json
            json.dump(result_log, f)
    
    def json_to_dataframe(self, json_log_list):
        temp_json_list = list()
        for record in json_log_list:
            new_json_record = dict()
            try: new_json_record['ProcessId'] = str(int(record['SourceProcessId']))
            except: continue
            new_json_record['Image'] = record['SourceFilePath']
            new_json_record['EventID'] = record['Action']
            new_json_record['CommandLine'] = record['SourceCommandLine']
            temp_json_list.append(new_json_record)
        return temp_json_list

    
    def preprocessing(self, dataframe):
        fields = ['ProcessId', 'EventID', 'Image', 'CommandLine']
        newdf = dataframe[fields]
        # drop all records where ProcessId in NaN (happens for WMI events, cannot classify [TODO: think how to overcome and add to dataset])
        newdf = newdf[~newdf.ProcessId.isna()]

        # # drop EventID 5 - ProcessTerminated as not valuable
        # newdf.drop(newdf[newdf.EventID == '5'].index, inplace=True)

        # get binary name (last part of "Image" after "\")
        newdf['binary'] = newdf.Image.str.split(r'\\').apply(lambda x: x[-1].lower())

        # same with binary pathes
        newdf['path'] = newdf.Image.str.split(r'\\').apply(lambda x: '\\'.join(x[:-1]).lower())

        newdf['arguments'] = newdf.CommandLine.fillna('empty').str.split().apply(lambda x: ' '.join(x[1:]))


        # add new features whether suspicious string are in arguments?
        # 1. base64?
        # will match at least 32 character long consequent string with base64 characters only
        b64_regex = r"[a-zA-Z0-9+\/]{64,}={0,2}"

        # map this search as 0 and 1 using astype(int)
        b64s = newdf['arguments'].apply(lambda x: re.search(b64_regex, x)).notnull()
        newdf['b64'] = b64s.astype(int)

        # matches if there's call for some file with extension (at the end dot) via UNC path
        unc_regex = r"\\\\[a-zA-Z0-9]+\\[a-zA-Z0-9\\]+\."
        uncs = newdf['arguments'][newdf['arguments'].apply(lambda x: re.search(unc_regex, x)).notnull()]

        url_regex = r"https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*)"
        urls = newdf['arguments'].apply(lambda x: re.search(url_regex, x)).notnull()

        # verified pd.concat part - merges two boolean series correctly
        newdf['unc_url'] = pd.concat([uncs, urls]).astype(int)

        newdf['network'] = newdf['Protocol'].notnull().astype(int)

        newdf = newdf[['ProcessId','binary','EventID','path', 'unc_url', 'b64', 'network']]
        # treat eventID as int8
        # newdf['EventID'] = newdf['EventID'].astype('int8')
        return newdf