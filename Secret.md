# Hack The Box - Secret

## This is my Writeup and walkthrough for Secret machine  from Hack The Box.

#### 1-Nmap

```
nmap -sC -sV -P 10.10.11.120
Starting Nmap 7.92 ( https://nmap.org ) at 2021-11-01 09:33 EET
Nmap scan report for 10.10.11.120
Host is up (0.20s latency).
Not shown: 997 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 97:af:61:44:10:89:b9:53:f0:80:3f:d7:19:b1:e2:9c (RSA)
|   256 95:ed:65:8d:cd:08:2b:55:dd:17:51:31:1e:3e:18:12 (ECDSA)
|_  256 33:7b:c1:71:d3:33:0f:92:4e:83:5a:1f:52:02:93:5e (ED25519)
80/tcp   open  http    nginx 1.18.0 (Ubuntu)
|_http-title: DUMB Docs
|_http-server-header: nginx/1.18.0 (Ubuntu)
3000/tcp open  http    Node.js (Express middleware)


```

## `User acess` 

i noticed that port `3000` is opened for `Node.js` okey lets explore port `80` .

![1](https://user-images.githubusercontent.com/36403473/156873493-9e112bdf-2483-43bd-bf1e-22e44ca3b428.png)

So i downloaded the source code,now lets dig in it the code so i will stop enum website and explore code first.

in this period my brain focus on way to find `RCE`. 

i found 4 important files in `node` folder on of them 

`private.js` 

```
router.get('/priv', verifytoken, (req, res) => {
   // res.send(req.user)

    const userinfo = { name: req.user }

    const name = userinfo.name.name;
    
    if (name == 'theadmin'){
        res.json({
            creds:{
                role:"admin", 
                username:"theadmin",
                desc : "welcome back admin,"
            }
        })
    }
    else{
        res.json({
            role: {
                role: "you are normal user",
                desc: userinfo.name.name
            }
        })
    }
})


router.get('/logs', verifytoken, (req, res) => {
    const file = req.query.file;
    const userinfo = { name: req.user }
    const name = userinfo.name.name;
    
    if (name == 'theadmin'){
        const getLogs = `git log --oneline ${file}`;
        exec(getLogs, (err , output) =>{
            if(err){
                res.status(500).send(err);
                return
            }
            res.json(output);
        })
    }
    else{
        res.json({
            role: {
                role: "you are normal user",
                desc: userinfo.name.name
            }
        })
    }
})

```

## lets explain our code 

#### 1- route to `/priv` we found that he only check on the name that  `name `==`theadmin`. 

#### 2- route `/log/` ``` exec(getLogs, (err , output) ``` here we got `RCE` he took `${file}`  and executed.

so that line was mistake that developer made 

now lets make our exploit but first we need to be `authenticated` and `authorized`. 

#### To be authenticated:

we need to create an account and get jwt token .
lets send `post` request to `register` 

what we need to create an account ????

```
    //create a user 
    const user = new User({
        name: req.body.name,
        email: req.body.email,
        password:hashPaswrod
    });

```
so we need to post (name&email&password) in `json` format 

![999](https://user-images.githubusercontent.com/36403473/156898976-4fb2249b-202e-410c-b082-695e872e6b39.png)


 
lets go to login page 

i got jwt token 

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2MjIzYjg5YTI3YzdlYzA0NTliMTkzNTEiLCJuYW1lIjoicHl0aG9uNDA0IiwiZW1haWwiOiJweXRob240MDRAem90ZS5jb20iLCJpYXQiOjE2NDY1MTIxMjV9.CgDdDke1S_4LcMxvGrcPSXphngv3Dtp20ovNTP8Rcx8

```


now i am authenticated 

![net](https://user-images.githubusercontent.com/36403473/156899116-5355330f-73fb-44ed-b205-264aa84b2b6c.png)


next step to be authorized :

so may mind go on changing the name in `jwt token` to `the admin` but i need to find `secret token` 

this secret token i found it in `git logs ` folders by using `git log -p` command 

![net2](https://user-images.githubusercontent.com/36403473/156900090-3aa990fc-7bd1-46e3-8a1e-0b9c2467a610.png)

 
![nnn](https://user-images.githubusercontent.com/36403473/156901422-7191c472-cdc3-4fd5-ac36-15832ee06b0b.png)

now let's try to access `/api/logs` that cant any non authorized user to access by `theadmin` user jwt token add with our revese shell 

![mmic](https://user-images.githubusercontent.com/36403473/156901616-0bbf3409-dbda-4d71-84c6-e52863ff7bc2.png)


![nr](https://user-images.githubusercontent.com/36403473/156901731-961653f6-dbff-47ff-a3ab-6e38e4af3b15.png)

