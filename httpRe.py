# coding: UTF-8
#!/usr/bin/python
#实测结果很坑爹，8核cpu，多进程发送10万个请求，urllib2用时44s,cpu占用20%，使用requests用时53s,cpu占用75%
import urllib2
from multiprocessing import Pool
import requests
import time
"""
def request(url):
    
    header = {
                "Connection": "close"
            }
 
    start_time = time.time()
    resp = urllib2.Request(url,)
    res_data = urllib2.urlopen(resp)
    res = res_data.read()
    print time.time()-start_time

"""
def request(url):
    start_time = time.time()
    resp = requests.get(url)
    print resp.status_code,time.time()-start_time

def start(url):
    pool = Pool(processes=8)
    for i in range(100000):
        pool.apply_async(request, (url,))
    pool.close()
    pool.join()

if __name__ == "__main__":
    sum_stime = time.time()
    start("http://183.134.68.69:8090/admin?leslie")
    print "sum_time: %s"% (time.time()-sum_stime)
