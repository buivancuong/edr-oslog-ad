import pandas as pd
from controller.data_input.df_file_input import DfFileInput

df = pd.read_feather('./data/logs.ft')

df_file_input = DfFileInput()
new_df = df_file_input.preprocessing(dataframe=df)
print(new_df)