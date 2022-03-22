# Hack The Box - Secret

<img width="237" alt="sec" src="https://user-images.githubusercontent.com/36403473/157329286-b8064943-e270-4533-83f5-91a89ee16492.png">

## This is my Writeup and walkthrough for Secret machine  from Hack The Box.

### Brief of attacks :

1- Source code review (nodejs)

2- JWT token

3- GIT LOGS

4- COREDUMP  

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

## `User access` 

i noticed that port `3000` is opened for `Node.js` okey let's explore port `80` .

![1](https://user-images.githubusercontent.com/36403473/156873493-9e112bdf-2483-43bd-bf1e-22e44ca3b428.png)

So i downloaded the source code,now let's dig in it the code so i will stop enum website and explore code first.

in this period my brain focus on way to find `RCE`. 

i found 4 important files in `node` folder one of them 

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

## let's explain our code

#### 1- route to `/priv` we found that code only check on the name parameter that  `name ==theadmin`. 

#### 2- route `/log/` ``` exec(getLogs, (err , output) ``` here we got `RCE`  that took `${file}`  and executed.

so that line was the mistake mistake that  the developer made 

now let's make our exploit but first we need to be `Authenticated` and `Authorized`. 

#### STEPS  To be `authenticated`:

we need to create an account and get `jwt` token .

so let's send `POST` request to `register` 

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


 
let's go to login page to `sign in` and finally got `jwt` token 

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2MjIzYjg5YTI3YzdlYzA0NTliMTkzNTEiLCJuYW1lIjoicHl0aG9uNDA0IiwiZW1haWwiOiJweXRob240MDRAem90ZS5jb20iLCJpYXQiOjE2NDY1MTIxMjV9.CgDdDke1S_4LcMxvGrcPSXphngv3Dtp20ovNTP8Rcx8

```


Now I am authenticated 

![net](https://user-images.githubusercontent.com/36403473/156899116-5355330f-73fb-44ed-b205-264aa84b2b6c.png)


#### STEPS to be `authorized` :

so my mind go on changing the name in `jwt token` to `the admin` but i need to find `secret token` first.

this secret token i found it in `git logs ` folders by using `git log -p` command 

![net2](https://user-images.githubusercontent.com/36403473/156900090-3aa990fc-7bd1-46e3-8a1e-0b9c2467a610.png)

 
![nnn](https://user-images.githubusercontent.com/36403473/156901422-7191c472-cdc3-4fd5-ac36-15832ee06b0b.png)

let's try to access `/api/logs` that can't any non authorized user to access by `theadmin` user jwt token add with our revese shell 

![mmic](https://user-images.githubusercontent.com/36403473/156901616-0bbf3409-dbda-4d71-84c6-e52863ff7bc2.png)


![nr](https://user-images.githubusercontent.com/36403473/156901731-961653f6-dbff-47ff-a3ab-6e38e4af3b15.png)

### `ROOT ACCESS`


now we have an intial access let's start chapter.

before of all i usually  i check sudo writes by `sudo -l` but now thing is interest ,one of my enumeration our many pentester to use script like `linpeas` to enum server but let make it last try.


after some time i found a binary file in `/opt/` directory with `root` rights with `c `code file 


### let's check this code 
```
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <dirent.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <linux/limits.h>

void dircount(const char *path, char *summary)
{
    DIR *dir;
    char fullpath[PATH_MAX];
    struct dirent *ent;
    struct stat fstat;

    int tot = 0, regular_files = 0, directories = 0, symlinks = 0;

    if((dir = opendir(path)) == NULL)
    {
        printf("\nUnable to open directory.\n");
        exit(EXIT_FAILURE);
    }
    while ((ent = readdir(dir)) != NULL)
    {
        ++tot;
        strncpy(fullpath, path, PATH_MAX-NAME_MAX-1);
        strcat(fullpath, "/");
        strncat(fullpath, ent->d_name, strlen(ent->d_name));
        if (!lstat(fullpath, &fstat))
        {
            if(S_ISDIR(fstat.st_mode))
            {
                printf("d");
                ++directories;
            }
            else if(S_ISLNK(fstat.st_mode))
            {
                printf("l");
                ++symlinks;
            }
            else if(S_ISREG(fstat.st_mode))
            {
                printf("-");
                ++regular_files;
            }
            else printf("?");
            printf((fstat.st_mode & S_IRUSR) ? "r" : "-");
            printf((fstat.st_mode & S_IWUSR) ? "w" : "-");
            printf((fstat.st_mode & S_IXUSR) ? "x" : "-");
            printf((fstat.st_mode & S_IRGRP) ? "r" : "-");
            printf((fstat.st_mode & S_IWGRP) ? "w" : "-");
            printf((fstat.st_mode & S_IXGRP) ? "x" : "-");
            printf((fstat.st_mode & S_IROTH) ? "r" : "-");
            printf((fstat.st_mode & S_IWOTH) ? "w" : "-");
            printf((fstat.st_mode & S_IXOTH) ? "x" : "-");
        }
        else
        {
            printf("??????????");
        }
        printf ("\t%s\n", ent->d_name);
    }
    closedir(dir);

    snprintf(summary, 4096, "Total entries       = %d\nRegular files       = %d\nDirectories         = %d\nSymbolic links      = %d\n", tot, regular_files, directories, symlinks);
    printf("\n%s", summary);
}


void filecount(const char *path, char *summary)
{
    FILE *file;
    char ch;
    int characters, words, lines;

    file = fopen(path, "r");

    if (file == NULL)
    {
        printf("\nUnable to open file.\n");
        printf("Please check if file exists and you have read privilege.\n");
        exit(EXIT_FAILURE);
    }

    characters = words = lines = 0;
    while ((ch = fgetc(file)) != EOF)
    {
        characters++;
        if (ch == '\n' || ch == '\0')
            lines++;
        if (ch == ' ' || ch == '\t' || ch == '\n' || ch == '\0')
            words++;
    }

    if (characters > 0)
    {
        words++;
        lines++;
    }

    snprintf(summary, 256, "Total characters = %d\nTotal words      = %d\nTotal lines      = %d\n", characters, words, lines);
    printf("\n%s", summary);
}


int main()
{
    char path[100];
    int res;
    struct stat path_s;
    char summary[4096];

    printf("Enter source file/directory name: ");
    scanf("%99s", path);
    getchar();
    stat(path, &path_s);
    if(S_ISDIR(path_s.st_mode))
        dircount(path, summary);
    else
        filecount(path, summary);

    // drop privs to limit file write
    setuid(getuid());
    // Enable coredump generation
    prctl(PR_SET_DUMPABLE, 1);
    printf("Save results a file? [y/N]: ");
    res = getchar();
    if (res == 121 || res == 89) {
        printf("Path: ");
        scanf("%99s", path);
        FILE *fp = fopen(path, "a");
        if (fp != NULL) {
            fputs(summary, fp);
            fclose(fp);
        } else {
            printf("Could not open %s for writing\n", path);
        }
    }

    return 0;
}
```
## `Core Dump`

After analysing:

this code take an file and give us information about 

``` 
Total characters  
Total words       
Total lines       
```
there is an interesting line :
`    // Enable coredump generation
    prctl(PR_SET_DUMPABLE, 1);
`
 #### What is `CORE DUMP` ?? 
A core dump consists of the recorded state of the working memory of a computer program at a specific time, generally when the program has terminated abnormally (crashed). Core dumps are often used to assist in diagnosing and debugging errors in computer programs.

A core dump file was found in this directory. The content of core dump files are highly sensitive as they contain the extact contents of the working memory including credentials, user data and so on.

 for more details check wiki [coredump](https://en.wikipedia.org/wiki/Core_dump)

for more details about `coredump` attack this juicy report [exploit][https://alephsecurity.com/2021/10/20/sudump/]

#### what we can do and how exploit occur ???? 
 To generate `core dump` file we need program to be crashed but how!!

an easy way we need to use `linux signals` : (if you dont linux signals check this bro [linux signals](https://www.educative.io/edpresso/what-are-linux-signals)

we will open another tab and use` kill -SIGKILL PID` command to kill process of `count` program.

let's find the ID of process by `ps -aux` command 

![1](https://user-images.githubusercontent.com/36403473/159387921-2326f877-c914-471f-bd1f-85e6ab1b4820.png)

before killing process i will make program read `/root/root.txt` and crash.

![2](https://user-images.githubusercontent.com/36403473/159388713-569c4290-adaf-49a6-868b-2f1a04531171.png)

now let's see what is happened in `core dump` file 

![3](https://user-images.githubusercontent.com/36403473/159388718-b842aa8d-d9d0-4e61-aae2-901cb571d9e3.png)

using `strings` command to make file simple

![4](https://user-images.githubusercontent.com/36403473/159388719-4308994d-bd7a-4273-bfdf-dd2d27ab4ba6.png)

I wish you to be happy to read my report 

........................................................................<!FINALLY_PWN!>......................................................................................................


