# NanoWAF
a nano waf based on openresty.

### 背景

这个项目大概启于2015年，当时市面上很多公司都或多或少的在使用WAF做一些基本网络防御。

起这个项目的主要的点是，当时手上有一堆的其他公司的JSONP漏洞，还有一些市面上常见工具比如SQLMap之类的RCE漏洞，无处施展，干脆就做个WAF+蜜罐。然后还有就是一些线上业务，在攻击止血阶段特别麻烦，业务还不如安全了解整个流量传递的过程，安全不得已自己上手去控制流程。

然后WAF这些东西吧，市面上商业的都太沉重，动不动硬件盒子黑洞路由，云WAF呢又得这个域名那个证书，然后开源WAF呢，把Nginx的性能压测都从十几万打到剩6000qps了，实在无奈，选择了自己写一个。
于是诞生了这个waf，专门为小而美定制，在小型项目里，配合安全工程师的猥琐思路，在对抗层面能起到很好的效果。而且鲁棒性高，即便WAF挂了也不影响业务。

### 定位

这不是一个标准的waf，这是一个HTTP流量层切面，主要用来给安全工程师在web接口处快于业务能快速做出安全响应。（其实包括后来什么apisix，kong之类也能实现这些东西，仁者见仁了）
所以在这层上，抛弃了常见的那些那些安全规则，比如现代的网络结构里，大部分的扫描可能对于业务来说是没有意义的，**一个java写的server，要防止.asp架构的漏洞纯属在浪费资源，属于懒政，好的安全防护不能让安全成为业务瓶颈**。


### 思路

NanoWAF的思路特别传统，依然是以规则检测为起手，其实就是使用lua去实现了nginx里各个资源的动态规则，然后配合不同的Action来做不同的事情。
规则的设计是尽可能做到短小精干，不参与复杂的逻辑，抛弃掉各种共享内存之类的复杂Cache。让Nginx还是全力以赴的在转发上做文章，保证性能，不参与过多的计算。
所谓越小越灵活，把规则的定制和使用交给安全工程师。


### 使用
NanoWAF的启用，依赖于核心nanowaf.lua, 对熟悉lua的朋友来说，代码不算复杂，几个Action(动作)，几个Method(匹配规则)，一个并规则检测引擎，完了，如果有需要可以自己改。
启用WAF的方式是在Nginx上引用nanowaf.lua, 并在需要检测的节点上，比如server, location, if之类的节点上引入一个规则的check函数，可以使用pcall来增强鲁棒性。
同时为了保证不做更多的内存开销还有规则的一致性检查，每个nginx的进程都会定时从远端（或者本地）获取一份规则列表，存放在Module级内存里，这样避免了进程之间的无效同步。


### 使用思路
看代码可知，Method里实现了几个基本的定义，比如equals, startswith, endswith, contains, regex, iregex, ipcontains之类然后传入mz和pattern作为比对，当然还有rev是值反标记。
如果比对上，就进入到执行Action到条件里，那Action分为 
  + hijack: 劫持请求，不让请求到原站，并返回自定义数据
  + deny: (hijack的一种)
  + mirror: 套路深刻
  + redirect: 跳转
  + tags: 对请求进行标记向下传递
  
这里边集中讲一下mirror这个鬼
  + mirror的意思是，把请求先转发给我的一个自定义http服务器，然后等待这个http服务器对于请求处理的返回，判断其header里是否有特定字段，并且将特定字段以Action的方式进行执行
  **也就是说，可以通过Mirror来实现及其复杂的检测流程**
  + 比如接到http请求时，可以去数据库查询一下请求资源的所属，防止水平越权漏洞。
  + 比如在接到http请求时，可以直接到redis等缓存里去设置一些信息，和原站逻辑做一些约定，告诉原站要做哪些事情
  + 比如在接到http请求时，判断攻击是否曾经在历史上出现过，如果有，就再mirror到下一层做控制
  
#### 举几个例子:
  + 曾经某被抓的互联网金融公司，在页面上要求填写我站的用户名和登入短信验证码，用来窃取用户数据。安全工程师经过分析发现，该请求的特征为请求时待上了一个特殊header, XXX: YYY
  
  于是这么写代码
  ```python
  import waf
  import json
  from basemodel import LoginModelMock       #几个Mock是对业务服务端能力的封装
  from basemodel import MessageModelMock
  from basemodel import SecurityModelMock
  
  @waf.regist({"name":"anti_thief","action":"mirror","rule":[{"mz":"http_XXX","method":"equals","pattern":"YYY"}]}) #这里是动态给服务端注册一个规则
  @waf.on_mirror_request
  def process_request(request, response):
      uid = LoginModelMock.mockLogin(request)   #模拟它这次登入，获得用户的id
      if uid:
          MessageModelMock.sendMessage(uid, "检测到您的账户可能填写在钓鱼网站上，个人信息已遭到失窃。本次获取您信息的攻击已被拦截，请注意个人信息防范。") #给用户pushapp消息
          LoginModelMock.kickUserSession(uid)   #剔除掉现有的Session
          SecurityModelMock.addBlackListIP(request.remote_addr, "phishing", "phishing from XXX", 86400*5)。  # 告诉其他风控系统这个IP有危险
      response.add_header('x-checkstatus': json.dumps(["deny",{"code":401}]))    # 告诉waf，返回401，请求就不要给原站了
  ```
  
 这样，用户手机会接到一条app推送，告诉他存在风险，第二，阻止了登入请求，返回了失败，第三，还加了这个公司的IP黑名单
 
 这样WAF还能和系统去联动，完成非常复杂的功能。
 
 
 
 
 #### [2022.10.03] 今天先写到这，过几天上传界面和控制端服务器。。。。然后再写点猥琐的
 
 
 其实老实说，界面是个很傻缺的东西（我特别不爱写界面）
 在前厂使用的安全架构是
 
 ```
 gateway -----+
              +--------> backend server (real server)
 wafcore -----+
    |
    +-----mirror----> (nginx mirror center) -------> (dynamic waf proccssor).py
    |                      |
    +---------------> (policyserver)
 ```
 
 这个nginx mirror center主要负责注册和卸载规则，同时根据ruleid转发相应的规则到后端的dynamic waf processor做处理。
 dynamic waf processor的主要用途就是waf的mirror逻辑本身
 这里有个小tip: nginx的connection要是断开了，会产生一个epoll断开的事件，会自行返回502， 只要hook这个事件，就可以做到规则摘除，同时再给gateway反馈不做任何事情的消息，请求就可以通过了， 根据这个原理，前场的waf就是一个可插拔的工具
 + 其他地方看到有要防护的地方，很快的用tornado写一个httpserver(用go、rust写也行)，启动时自动注册相应的规则到服务端，waf会在n秒后自动同步到规则集后开始转发
 + 如果不要防护了，很简单，直接ctrl+c结束这个进程，防护就会自动下线了。
所以在前厂做流量攻防的流程变成如下：

  + 从准实时日志、离线日志里筛选出需要防护或者有被攻击风险的接口们
  + 思考方案，协商业务通知，编写waf脚本
  + 启动waf脚本止血。
  + 跟业务说，这个脚本只能跑1天，1天之后防护就失效了你们特么赶紧修。
  + 中间参杂着各种对抗，各种ctrl+c改代码，业务不用太多感知。
 

[2022.10.8] 还没写完，打算根据上边说的可插拔调用，传个简单架构工具。今天开始特么重保了，先写到这。下次更新一些猥琐方案上来。
