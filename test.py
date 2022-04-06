from warnings import simplefilter
import pandas as pd
from sklearn import preprocessing
from controller.data_input.df_file_input import DfFileInput
from controller.data_output.groupby_transform import GroupTransform
from model.model import METRICS, model_simplest, OPT

df = pd.read_feather('./data/logs.ft')

df_file_input = DfFileInput()
new_df = df_file_input.preprocessing(dataframe=df)

MAX_TIMESTEPS = 128
# number of features (except ProcessId itself)
N = len(new_df.columns) - 1

gt = GroupTransform()
train_X, val_X, train_y, val_y = gt.groupby_transform(dataframe=new_df, column='ProcessId', MAX_TIMESTEPS=MAX_TIMESTEPS, N=N)

print("train_X: " + str(len(train_X)) + " :: " + str(train_X.shape))
print(train_X)
print()
print("train_y: " + str(len(train_y)) + " :: " + str(train_y.shape))
print(train_y)
print()
print("val_X: " + str(len(val_X)) + " :: " + str(val_X.shape))
print(val_X)
print()
print("val_y: " + str(len(val_y)) + " :: " + str(val_y.shape))
print(val_y)

model = model_simplest(MAX_TIMESTEPS=MAX_TIMESTEPS, OH_DIMENSION=N)
model.compile(optimizer=OPT, loss='binary_crossentropy', metrics=METRICS)
print("Training:~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
model.fit(x=train_X, y=train_y, batch_size=32, epochs=10)
print("Predict:~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
print(model.predict(x=val_X))
model.save('model/model_simplest')
