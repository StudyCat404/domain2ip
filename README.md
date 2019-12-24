# domain2ip

# 使用
domain2ip.py -h  
optional arguments:  
-h, --help                            show this help message and exit  
-w WORDLIST, --wordlist WORDLIST      Lines contain domain names, one per line  
-p PORTS, --port PORTS                Ports to scan  
-t THREADS, --threads THREADS         Number of threads  
-o OUTPUT_FILENAME, --output OUTPUT_FILENAME Write output to a csv file  
`
def output(data):
    data = parser(data)
    print(data)
    with open('subdomains.txt', 'a') as f:
        for line in data:
            f.write(line+"\n")
`
# 截图
 ![Image text](https://github.com/telllpu/domain2ip/blob/master/Capture.PNG)
