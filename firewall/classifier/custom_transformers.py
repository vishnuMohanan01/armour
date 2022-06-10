from sklearn.base import BaseEstimator, TransformerMixin


class DataFrameSelector(BaseEstimator, TransformerMixin):
    def __init__(self, col_names):
        self.col_names = col_names

    def fit(self, X, y=None):
        return self

    def transform(self, X):
        return X[self.col_names].values
