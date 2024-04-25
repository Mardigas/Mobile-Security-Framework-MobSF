import joblib

import numpy as np

import yaml

from mobsf.customscripts.rf.rules.dvm_permissions import DVM_PERMISSIONS
from mobsf.customscripts.rf.rules.android_manifest_desc import MANIFEST_DESC
from mobsf.customscripts.rf.rules.features import EXCLUSIONS, FEATURELIST


def create_dataset(data):
    size = len(FEATURELIST) - len(EXCLUSIONS)
    dataset = np.zeros((1, size))
    permissions = list(data['permissions'].keys())

    for i in range(len(permissions)):
        permissions[i] = permissions[i].split('.')[-1]
    feature_index = 0

    for key in DVM_PERMISSIONS['MANIFEST_PERMISSION'].keys():
        if key not in EXCLUSIONS:
            if key in permissions:
                dataset[0][feature_index] = 1
            else:
                dataset[0][feature_index] = 0
            feature_index += 1

    manifest = list(data['manifest_analysis']['manifest_findings'])
    for i in range(len(manifest)):
        manifest[i] = manifest[i]['rule']
    for key in MANIFEST_DESC.keys():
        if key not in EXCLUSIONS:
            if key in manifest:
                dataset[0][feature_index] = 1
            else:
                dataset[0][feature_index] = 0
            feature_index += 1

    api = data['android_api'].keys()
    with open('mobsf/customscripts/rf/rules/android_apis.yaml', 'r') as stream:
        api_rules = yaml.safe_load(stream)
    for key in api_rules:
        if key['id'] not in EXCLUSIONS:
            if key['id'] in api:
                dataset[0][feature_index] = 1
            else:
                dataset[0][feature_index] = 0
            feature_index += 1

    code = data['code_analysis']['findings'].keys()
    with open('mobsf/customscripts/rf/rules/android_rules.yaml', 'r') as stream:
        code_rules = yaml.safe_load(stream)

    for key in code_rules:
        if key['id'] not in EXCLUSIONS:
            if key['id'] in code:
                dataset[0][feature_index] = 1
            else:
                dataset[0][feature_index] = 0
            feature_index += 1
    return dataset


def predict(data):

    dataset = create_dataset(data)
    model = joblib.load('mobsf/customscripts/rf/trained_rf_model.joblib')
    res = model.predict_proba(dataset).tolist()[0]

    if res[1] >= 0.5:
        res[1] = round(res[1] * 100, 3)
        return [1, res[1]]
    else:
        res[0] = round(res[0] * 100, 3)
        return [0, res[0]]
