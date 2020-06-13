#using 'time' for time related operation
#using 'urlib' for http related operation
#using 'html' for html related operation
import os
import urllib
import time 
import html
from sklearn.linear_model import LogisticRegression
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split


def get_query_list(filename):
    filepath = "../input/malicious-request-dataset/" + filename
    data = open(filepath, 'r', encoding='UTF-8').readlines()
    query_list = []
    for d in data:
        # decoding(解码)
        d = str(urllib.parse.unquote(d))   # converting url encoded data to simple string
        query_list.append(d)
    return list(set(query_list))
    
    
# tokenizer function, this will make 3 grams of each query
# eg: www.foo.com/1 will be transformed to ['www','ww.','w.f','.fo','foo','oo.','o.c','.co','com','om/','m/1']
def get_ngrams(query):
    tempQuery = str(query)
    ngrams = []
    for i in range(0, len(tempQuery)-3):
        ngrams.append(tempQuery[i:i+3])
    return ngrams
    
    
# The main function
if __name__ == '__main__':
    
    # Get normal request and print some expamles
    good_query_list = get_query_list('goodqueries.txt')
    print(u"Normal Request: ", len(good_query_list)) # using unicode to encode characters
    print(u"For Example:")
    for  i in range(0, 5):
        print(good_query_list[i].strip('\n'))
    print("\n")
        
    # Get malicious request and print some examples
    bad_query_list = get_query_list('badqueries.txt')
    print(u"Malicious Request: ", len(bad_query_list))
    print(u"For Example:")
    for  i in range(0, 5):
        print(bad_query_list[i].strip('\n'))
    print("\n")

    # Preprocessing (预处理 good_y标记为0 bad_y标记为1)
    good_y = [0 for i in range(0, len(good_query_list))]
    print(good_y[:5])
    bad_y = [1 for i in range(0, len(bad_query_list))]
    print(bad_y[:5])
    
    queries = bad_query_list + good_query_list
    y = bad_y + good_y

    # converting data to vectors
    # TfidfTransformer + CountVectorizer  =  TfidfVectorizer
    # sklearn.feature_extraction.text.TfidfVectorizer() is used to convert a collection of raw documents to a matrix of TF-IDF features.
    vectorizer = TfidfVectorizer(tokenizer=get_ngrams)

    # Preparing for model training（把不规律的文本字符串列表转换成规律的 ([i,j], tdidf值) 的矩阵X)
    # (用于下一步训练逻辑回归分类器)
    X = vectorizer.fit_transform(queries)
    print(X.shape)

    # Split dataset for teaing and testing
    # (使用train_test_split分割X,y列表)
    # (X_train矩阵的数目对应y_train列表的数目(一一对应),用来训练模型)
    # (X_test矩阵的数目对应y_test列表的数目(一一对应),用来测试模型的准确性)
    # Consult: https://blog.csdn.net/qq_39355550/article/details/82688014
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=20, random_state=42)

    # Train the model and test it
    # (使用逻辑回归方法模型)
    LR = LogisticRegression()
    # (训练模型)
    LR.fit(X_train, y_train)
    # (对模型的准确度进行计算)
    print('模型的准确度:{}'.format(LR.score(X_test, y_test)))
    print("\n")
    # (对新的请求列表进行预测)
    new_queries = ['www.foo.com/id=1<script>alert(1)</script>',
                   'www.foo.com/name=admin\' or 1=1','abc.com/admin.php',
                   '"><svg onload=confirm(1)>',
                   'test/q=<a href="javascript:confirm(1)>',
                   'q=../etc/passwd',
                   '/stylesheet.php?version=1331749579',
                   '/<script>cross_site_scripting.nasl</script>.idc',
                   '<img \x39src=x onerror="javascript:alert(1)">',
                   '/jhot.php?rev=2 |less /etc/passwd']
    # 矩阵转换
    X_predict = vectorizer.transform(new_queries)
    res = LR.predict(X_predict)

    #Print the result
    res_list = []
    for q,r in zip(new_queries, res):
        tmp = 'Normal Request' if r == 0 else 'Malicious Request'
        q_entity = html.escape(q)
        # Consult: https://www.jianshu.com/p/d896e3017417
        res_list.append({'url':q_entity,'res':tmp})

    for n in res_list:
        print(n)
