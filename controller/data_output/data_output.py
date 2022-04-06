from abc import ABC, abstractclassmethod

class DataOutput:
    @abstractclassmethod
    def transform(self, dataframe):
        pass