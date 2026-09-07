import joblib 
cols=joblib.load("models/feature_columns.pkl")
print(len(cols))
for i,c in enumerate(cols):
    print(i,c)