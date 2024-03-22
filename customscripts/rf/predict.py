import joblib
import numpy as np
import yaml

# feature_names = model.estimators_[0].feature_importances_.argsort()[::-1]
# feature_names_list = [FEATURELIST[i] for i in feature_names]
# tree.export_graphviz(model.estimators_[0], out_file="tree.dot", 
#                      class_names=['goodware', 'malware'], 
#                      feature_names=feature_names_list, 
#                      filled=True, rounded=True, special_characters=True)

# os.system("dot -Tpng tree.dot -o tree.png")

from customscripts.rf.rules.dvm_permissions import DVM_PERMISSIONS
from customscripts.rf.rules.android_manifest_desc import MANIFEST_DESC

def create_dataset(data):

    dataset = np.zeros((1, 469))
    
    permissions = list(data["permissions"].keys())
    for i in range(len(permissions)):
        permissions[i] = permissions[i].split(".")[-1]

    feature_index = 0

    for key in DVM_PERMISSIONS["MANIFEST_PERMISSION"].keys():
        if key in permissions:
            dataset[0][feature_index] = 1
            print("MATCH: ", key)
        else:
            dataset[0][feature_index] = 0
        feature_index += 1
    
    manifest = list(data["manifest_analysis"]["manifest_findings"])
    # TODO dict > list of dicts > key "rule"
    for key in MANIFEST_DESC.keys():
        if key in manifest:
            dataset[0][feature_index] = 1
            print("MATCH: ", key)
        else:
            dataset[0][feature_index] = 0
        feature_index +=1

    api = (data["code_analysis"].keys())
    print(api)
    with open("customscripts/rf/rules/android_apis.yaml", "r") as stream:
        api_rules = yaml.safe_load(stream)
    for key in api_rules:
        if key["id"] in api:
            dataset[0][feature_index] = 1
            print("MATCH: ", key["id"])
        else:
            dataset[0][feature_index] = 0
        feature_index +=1

    print(dataset)

    return True

def predict(data):

    dataset = create_dataset(data)
    return True
    model = joblib.load(model_path)
    res = model.predict_proba(dataset)

    if res[0][1] >= 0.5:
        print(f"{round(res[0][1]*100,4)}% probability of being malware")
        return (1, res)
    else:
        print(f"{round(res[0][0]*100,4)}% probability of being goodware")
        return (0, res)
