import requests
import hashlib
import sys


def request_api_data(query_char):
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(f'Error fetching {res.status_code}')
    return res


def get_password_leak_count(hashes, hash_to_check):
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == hash_to_check:
            return count
    return 0


def pwned_api_check(password):
    sha1password = hashlib.sha1(password.encode('UTF-8')).hexdigest().upper()
    first5_char, tail = sha1password[0:5], sha1password[5:]
    response = request_api_data(first5_char)
    return get_password_leak_count(response, tail)


def main(args):
    for password in args:
        count = pwned_api_check(password)
        if count:
            print(f'Password {password} was found {count} times')
        else:
            print(f'No matches found for {password}')
    return "done"

if __name__ == '__main__':
    with open('passwds.txt', 'r') as file:
       for p in file.read().splitlines():
          main(list(p.split(',')))

    #sys.exit(main(sys.argv[1:]))

