from abc import ABC, abstractclassmethod

class DataInput:
    @abstractclassmethod
    def preprocessing(self, dataframe):
        pass
    