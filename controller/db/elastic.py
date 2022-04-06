from elasticsearch import Elasticsearch
import logging
import json

class Elastic:
    def __init__(self, elastic_cfg_filepath):
        with open(elastic_cfg_filepath) as elastic_cfg_file:
            elastic_cfg = json.load(elastic_cfg_file)
        self.__elastic = elastic_cfg['elastic']
        self.__es = Elasticsearch([self.__elastic['addr']])
    
    def get_system_log(self, os, purpose):
        pass