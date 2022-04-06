from controller.data_output.data_output import DataOutput

from sklearn.preprocessing import LabelEncoder
from tensorflow.keras.preprocessing.sequence import pad_sequences
from datetime import datetime
import numpy as np

class GroupTransform(DataOutput):
    def __init__(self):
        pass

    def groupby_transform(self, dataframe, column, MAX_TIMESTEPS, N):
        total = len(dataframe.groupby(column))
        start = datetime.now()
        print(f"Started at: {start}")

        print(f"Total categories of '{column}': '{total}'")
        print(f"Unique values: {dataframe[column].nunique()}")

        # Initialize Numpy Arrays with correct shape
        train_X = np.empty(shape=(0, MAX_TIMESTEPS, N)).astype(np.int16)
        train_y = np.empty(shape=(0,1)).astype(np.int16)
        val_X = np.empty(shape=(0, MAX_TIMESTEPS, N)).astype(np.int16)
        val_y = np.empty(shape=(0,1)).astype(np.int16)

        # get encode object for string columns
        binary_le = LabelEncoder().fit(['OTHER'] + list(dataframe['binary'].unique()))
        path_le = LabelEncoder().fit(['OTHER'] + list(dataframe['path'].unique()))
        
        # load malicious/valid process lists
        with open(r'data/pid_valid.lst') as f:
            valid_lst = [x.strip() for x in f.readlines()]
        with open(r'data/pid_malicious.lst') as f:
            mal_lst = [x.strip() for x in f.readlines()]
        
        with open(r'data/validation_pid.lst') as f:
            validation_data = f.readlines()

        validation_pids = []
        for line in validation_data:
            if ':' in line:
                validation_pids.append(line.split(':')[0])

        try:
            for i, (value, df) in enumerate(dataframe.groupby(column)):
                # skip processes with less than 3 events 
                # - too little to identify malicious activity
                if len(df) < 4:
                    continue
                
                if value in valid_lst:
                    temp_y = np.array([0]).reshape(1,1)
                elif value in mal_lst:
                    temp_y = np.array([1]).reshape(1,1)
                else:
                    print(f'Unclassified ProcessID: {value}')
                    raise Exception

                # Create 3D array from 
                temp_X = np.hstack((
                    df[['EventID', 'unc_url', 'b64', 'network']].to_numpy(),
                    binary_le.transform(list(df['binary'])).reshape(-1,1),
                    path_le.transform(list(df['path'])).reshape(-1,1)
                ))

                # PADDING
                temp_X = pad_sequences(temp_X.T, maxlen=MAX_TIMESTEPS).T
                
                # adding this example to actual set
                if value in validation_pids:
                    val_X = np.concatenate((val_X, temp_X.reshape(1, MAX_TIMESTEPS, N)))
                    val_y = np.concatenate((val_y, temp_y))
                else:
                    train_X = np.concatenate((train_X, temp_X.reshape(1, MAX_TIMESTEPS, N)))
                    train_y = np.concatenate((train_y, temp_y))
            
            end = datetime.now()
            print(f"Ended at: {end}")
            print(f"Script completion time: {end - start}")
            return train_X, val_X, train_y, val_y

        except KeyboardInterrupt:
            end = datetime.now()
            print(f"Ended at:\niteration:{i}\ntime:{end}")
            print(f"Script completion time: {end - start}")
            return train_X, val_X, train_y, val_y
    
