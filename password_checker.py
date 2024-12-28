import requests
import sys
import hashlib

def request_data_to_api(query_char):
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(f'Error occured{res.status_code}, Check the API and try again!')
    return res

def get_password_count(hashes, hash_to_check):
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == hash_to_check:
            return count
    return 0
    

def pwned_api_check(psassword):
    sha1password = hashlib.sha1(psassword.encode('utf-8')).hexdigest().upper()
    first_five_char, rest = sha1password[:5], sha1password[5:]
    response = request_data_to_api(first_five_char)
    return get_password_count(response, rest)

def main(args):
    for password in args:
        count = pwned_api_check(password)
        if count:
            print(f'{password} was found{count} times ... change your password for securety')
        else:
            print(f'{password} was not Used any more')
    return 'Done!'
if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))



