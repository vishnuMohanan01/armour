from sklearn.pipeline import FeatureUnion
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder
from sklearn.preprocessing import StandardScaler

from firewall.classifier.custom_transformers import DataFrameSelector
from firewall.utils.model_utils import get_req_cols


def create_pipeline():
    """
    creates numerical and categorical pipelines,
    combines it and returns the full pipeline
    """

    req_cols = get_req_cols()

    num_pipeline = Pipeline([
        ('selector', DataFrameSelector(req_cols['numerical_cols'])),
        ('std_scaler', StandardScaler())
    ])

    cat_pipeline = Pipeline([
        ('selector', DataFrameSelector(req_cols['categorical_cols'])),
        ('one_hot_encoder', OneHotEncoder(sparse=False))
    ])

    return FeatureUnion(transformer_list=[
        ('num_pipeline', num_pipeline),
        ('cat_pipeline', cat_pipeline)
    ])
