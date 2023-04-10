from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
import urllib.parse
from sklearn import tree
from sklearn import metrics
import io
from sklearn.svm import LinearSVC
from sklearn.metrics import confusion_matrix
import pickle

normal_file_raw = 'normalTrafficTraining.txt'
anomaly_file_raw = 'anomalousTrafficTest.txt'

normal_file_parse = 'normalRequestTraining.txt'
anomaly_file_parse = 'anomalousRequestTest.txt'


def parse_file(file_in, file_out):
    fin = open(file_in)
    fout = io.open(file_out, "w", encoding="utf-8")
    lines = fin.readlines()
    res = []
    for i in range(len(lines)):
        line = lines[i].strip()
        if line.startswith("GET"):
            res.append("GET" + line.split(" ")[1])
        elif line.startswith("POST") or line.startswith("PUT"):
            url = line.split(' ')[0] + line.split(' ')[1]
            j = 1
            while True:
                if lines[i + j].startswith("Content-Length"):
                    break
                j += 1
            j += 1
            data = lines[i + j + 1].strip()
            url += '?' + data
            res.append(url)
    for line in res:
        line = urllib.parse.unquote(line).replace('\n', '').lower()
        fout.writelines(line + '\n')
    print("finished parse ", len(res), " requests")
    fout.close()
    fin.close()


def loadData(file):
    with open(file, 'r', encoding="utf8") as f:
        data = f.readlines()
    result = []
    for d in data:
        d = d.strip()
        if (len(d) > 0):
            result.append(d)
    return result


parse_file(normal_file_raw, normal_file_parse)
parse_file(anomaly_file_raw, anomaly_file_parse)

bad_requests = loadData('anomalousRequestTest.txt')
good_requests = loadData('normalRequestTraining.txt')

all_requests = bad_requests + good_requests
yBad = [1] * len(bad_requests)
yGood = [0] * len(good_requests)
y = yBad + yGood

vectorizer = TfidfVectorizer(
    min_df=0.0, analyzer="char", sublinear_tf=True, ngram_range=(3, 3))
X = vectorizer.fit_transform(all_requests)
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.1, random_state=21)

# logistic regression
lgs = LogisticRegression()
lgs.fit(X_train, y_train)
y_pred = lgs.predict(X_test)
score_test = metrics.accuracy_score(y_test, y_pred)
matrix = confusion_matrix(y_test, y_pred)
print("Score Logistic Regression :", score_test)
print("Confusion Matrix: ")
print(matrix)
# display precision, recall, f1-score, false positive rate, false negative rate
print(metrics.classification_report(y_test, y_pred))
filename = 'logisticregression_model.sav'
pickle.dump(lgs, open(filename, 'wb'))

# Decision Tree
dtc = tree.DecisionTreeClassifier()
dtc.fit(X_train, y_train)
y_pred = dtc.predict(X_test)
score_test = metrics.accuracy_score(y_test, y_pred)
matrix = confusion_matrix(y_test, y_pred)
print("Score Decesion Tree :", score_test)
print("Confusion Matrix: ")
print(matrix)
filename = 'decisiontreeclassifier_model.sav'
pickle.dump(lgs, open(filename, 'wb'))

# Linear SVM
linear_svm = LinearSVC(C=1)
linear_svm.fit(X_train, y_train)
y_pred = linear_svm.predict(X_test)
score_test = metrics.accuracy_score(y_test, y_pred)
matrix = confusion_matrix(y_test, y_pred)
print("Score Linear SVM :", score_test)
print("Confusion Matrix: ")
print(matrix)
filename = 'linearsvm_model.sav'
pickle.dump(lgs, open(filename, 'wb'))

# Random Forest
rfc = RandomForestClassifier(n_estimators=200)
rfc.fit(X_train, y_train)
y_pred = rfc.predict(X_test)
score_test = metrics.accuracy_score(y_test, y_pred)
print("Score Random Forest :", score_test)
print("Confusion Matrix: ")
print(matrix)
filename = 'randomforest_model.sav'
pickle.dump(lgs, open(filename, 'wb'))
