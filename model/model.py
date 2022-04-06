import tensorflow as tf
from tensorflow import keras
from sklearn.metrics import f1_score

METRICS = [
    keras.metrics.TruePositives(name='tp'),
    keras.metrics.FalsePositives(name='fp'),
    keras.metrics.TrueNegatives(name='tn'),
    keras.metrics.FalseNegatives(name='fn'), 
    # Precision: (TP) / (TP + FP)
    # what proportion of predicted Positives is truly Positive
    keras.metrics.Precision(name='precision'),
    # Recall: (TP) / (TP+FN)
    # what proportion of actual Positives is correctly classified
    keras.metrics.Recall(name='recall'),
    keras.metrics.AUC(name='auc'),
    keras.metrics.Accuracy(name='accuracy')
]
OPT = tf.keras.optimizers.Adam(learning_rate=0.005)

def model_simplest(MAX_TIMESTEPS, OH_DIMENSION):
    model_simplest = keras.Sequential()
    model_simplest.add(keras.layers.LSTM(units=32, dropout=0.2, recurrent_dropout=0.2, input_shape=(MAX_TIMESTEPS, OH_DIMENSION)))
    model_simplest.add(keras.layers.Dense(units=1, activation='sigmoid'))
    return model_simplest


def model_dd(MAX_TIMESTEPS, OH_DIMENSION):
    model_dd = keras.models.Sequential()
    model_dd.add(keras.layers.LSTM(units=32, dropout=0.2, recurrent_dropout=0.2, input_shape=(MAX_TIMESTEPS, OH_DIMENSION)))
    model_dd.add(keras.layers.Dropout(0.5))
    model_dd.add(keras.layers.Dense(units=32, activation='relu'))
    model_dd.add(keras.layers.Dense(units=1, activation='sigmoid'))
    return model_dd


# def model_deep(MAX_TIMESTEPS, OH_DIMENSION):
#     model_deep = keras.models.Sequential()
#     model_deep.add(keras.layers.LSTM)
#     model = keras.models.Sequential([
#     keras.layers.LSTM(128, dropout=0.2, recurrent_dropout=0.2, input_shape=[MAX_TIMESTEPS, OH_DIMENSION]),
#     #keras.layers.Dropout(0.5),
#     keras.layers.Dense(128, activation='relu'),
#     #keras.layers.Dropout(0.5),
#     keras.layers.Dense(16, activation='relu'),
#     keras.layers.Dense(1, activation='sigmoid')
#     ])
#     return model


# def model_deeper(MAX_TIMESTEPS, OH_DIMENSION):
#     model = keras.models.Sequential([
#     keras.layers.LSTM(128, dropout=0.2, recurrent_dropout=0.2, 
#                       input_shape=[MAX_TIMESTEPS, OH_DIMENSION], return_sequences=True),
#     keras.layers.LSTM(128, dropout=0.2, recurrent_dropout=0.2, input_shape=[MAX_TIMESTEPS, OH_DIMENSION]),
#     #keras.layers.Dropout(0.5),
#     keras.layers.Dense(128, activation='relu'),
#     #keras.layers.Dropout(0.5),
#     keras.layers.Dense(16, activation='relu'),
#     keras.layers.Dense(1, activation='sigmoid')
#     ])
#     return model


# def model_bidir(MAX_TIMESTEPS, OH_DIMENSION):
#     model = keras.models.Sequential([
#       keras.layers.Bidirectional(
#           keras.layers.LSTM(32, dropout=0.2, recurrent_dropout=0.2, input_shape=[MAX_TIMESTEPS, OH_DIMENSION]),
#       ),
#       #keras.layers.Dropout(0.5),
#       keras.layers.Dense(32, activation='relu'),
#       keras.layers.Dense(1, activation='sigmoid')
#       ])
#     return model


# def model_conv_rnn(MAX_TIMESTEPS, OH_DIMENSION):
#     model = keras.models.Sequential([
#                 keras.layers.Conv1D(filters=64, kernel_size=3, activation='relu', 
#                                     input_shape=[MAX_TIMESTEPS, OH_DIMENSION]),
#                 keras.layers.MaxPooling1D(pool_size=2),
#                 keras.layers.LSTM(64),
#                 keras.layers.Dropout(0.5),
#                 keras.layers.Dense(32, activation='relu'),
#                 keras.layers.Dense(1, activation='sigmoid')
#     ])
#     return model


# def model_conv_birnn(MAX_TIMESTEPS, OH_DIMENSION):
#     model = keras.models.Sequential([
#                 keras.layers.Conv1D(filters=64, kernel_size=3, activation='relu', input_shape=[MAX_TIMESTEPS, OH_DIMENSION]),
#                 keras.layers.MaxPooling1D(pool_size=2),
#                 keras.layers.Bidirectional(keras.layers.LSTM(64, dropout=0.2, recurrent_dropout=0.2)),
#                 keras.layers.Dropout(0.5),
#                 keras.layers.Dense(32, activation='relu'),
#                 keras.layers.Dense(1, activation='sigmoid')
#     ])
#     return model