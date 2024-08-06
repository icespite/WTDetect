# RQ1: The Application of Browser Fingerprinting (Review-A)
The concept of browser fingerprinting was proposed by [1]. Similar to HTTP Cookie, the original purpose of browser fingerprinting was to uniquely identify a particular browser. However, compared with HTTP Cookie, browser fingerprinting is more difficult to detect, since it leaves no persistent evidence of tagging on the user’s computer [1]. Additionally, Yang et.al. [2] found that more websites have started to use stateless web tracking techniques such as browser fingerprinting and 5,835 different JavaScript API-based trackers from 23,310 websites are identified.

Nevertheless, we have never absolutely characterized browser fingerprinting as a malicious method. Actually, we strongly agree that browser fingerprinting can be used for benign purposes, for example, web authentication and bot detection, including Google’s reCAPTCHA. However, there are concerns that browser fingerprinting may be used for cross-site tracking especially as mainstream browsers adopt aggressive policies against third-party cookies [3].

Given the possibility that browser fingerprinting can be used for third-party tracking, we detected the existence of both browser fingerprinting and storage-based methods to recognize third-party tracking comprehensively. The lack of benign applications of browser fingerprinting in this paper will be supplemented in the background section later.


# RQ2: Challenges of Detecting Tracking through Existing Web-based Methods (Review-A, B)

## OpenWPM-mobile and WTPatrol are not suitable for APP-based detection

WTDetect's process from data collection to analysis is different from these two. In a nutshell, they are both plugins that magically modify the browser, OpenWPM-mobile to emulate Android as much as possible, and WTPatrol to run directly on Android phones. After that they both flagged potential tracking behaviors through filter lists, and finally there was a large-scale analysis of these sites.

From the data collection process, they are analyzing the mobile versions of various popular websites, while we are analyzing the web content of third-party libraries in Android. The web here is only formally similar to what they analyze, but in reality it is completely different.

First of all, although the third library for Android can load advertisements through http requests, its purpose is not to display a web page that can be accessed by a browser. These URLs are generally not directly accessible to the user, nor do they act as a dependency on a website, and they serve a different goal than "serving content through a web page". This is an important reason why filter lists are largely ineffective.

In fact, when you visit them directly with a browser, they often don't fully load their dependencies or display ad content and hide their behavior. For example, [https://sf3-fe-tos.pglstatp-toutiao.com/obj/ad-pattern/renderer/675c4f/index.html](https://sf3-fe-tos.pglstatp-toutiao.com/obj/ad-pattern/renderer/675c4f/index.html) is an advertisement html loaded in the TalkingData sdk, and there is no advertisement content when you access it directly through a browser. But WTDetect can catch the advertisement content when the app is running.


<center>
    <img src="https://github.com/icespite/WTDetect/blob/main/images/image1.png?raw=true" style="zoom: 100%;" />
    <div><strong>Figure 1: The content obtained by WTDetect. (under the body tag is the advertisement)</strong></div>
    <br>
</center>
 


<center>
    <img src="https://github.com/icespite/WTDetect/blob/main/images/image2.png?raw=true" style="zoom: 100%;" />
    <div><strong>Figure 2: The content obtained directly with the browser. (no ads under the body tag)</strong></div>
    <br>
</center>

In other words, the data collection process of the above paper is completely invalid for our research objectives.

Furthermore, since they are in the form of third-party libraries in Android, there is no browser as a ready tool, and both OpenWPM-mobile and WTPatrol rely on browser extensions, which means that not only are they not able to collect data in full, but it can even be argued that they are completely unable to cope with current scenarios, let alone collect dynamic information such as API calls. Therefore, it is extremely difficult to recover source files and collect dynamic messages by directly accessing URLs like OpenWPM. And although the webview can theoretically be turned on in debug mode, we found in our experiments that it is basically incapable of fetching the content of advertisements. Our solution is to recover the actual HTML and JS files displayed and executed from the webview at runtime via frida.

The third is that our analysis revealed that many third-party libraries take advantage of Android's file-loading format by implementing ad-loaded pages stored in assets or hard-coded and then released into Android system files at runtime and deleted after running. Afterwards the dependencies are loaded through a form similar to the one below, which further leads to openwpm and WTPatrol not being able to properly analyze and load the pages and dependency files.

```javascript
const scriptSrc = "file:///storage/emulated/0/Android/data/com.justdeveloper.capiso/files/al/o609efb3_946c89268c09359505ba89e23a41de3700c5a954_v1_js_load.js";
if (scriptSrc.startsWith("https://") && !IS_WEB_UI_PREVIEW && !IS_GRAPHIC_STREAMING_ENABLED) {
    showFauxEndcardImmediately = true;
    var aTag = document.createElement("a");
    aTag.setAttribute("href", "applovin://com.applovin.sdk/template_error?error=playableCacheFailure&details=scriptSrc=" + scriptSrc);
    aTag.innerHTML = "empty";
    aTag.click();
} else {
    var script = document.createElement("script");
    script.type = "text/javascript";
    script.src = scriptSrc;
    document.head.appendChild(script);
}
```

```html
<script type="text/javascript" src="file:///android_asset/article/js/android.js"></script>
```

Overall, the two papers mentioned above rely heavily on the browser as a tool, while WTDetect faces a more complex situation.

Compared to desktop tracking, the third-party websites of these SDKs have unique tracking characteristics. Detailed explanations can be found at "RQ3: Differences between Desktop-based and APP-based Tracking".

From the classification and tagging process perspective, we have improved and optimized the classifier by moving away from relying solely on unreliable filter lists and proposing a detection method based on static taint propagation.

# RQ3: Differences between Desktop-based and APP-based Tracking (Review-A, B)

## The information third-party websites prefer to collect

Both third-party websites and normal websites may collect browser-related information, screen information, language information, etc. to generate fingerprints. However, fingerprints of third-party websites prefer to collect application and platform information (app name, package name, etc.), various ID numbers, platform-related information (Android, iOS) and other device and user information. The information that third-party websites prefer to collect is as follows:

+ Browser information: browser name, version, UA, etc.
+ OS information: OS name, version, etc.
+ Device information: screen length, width, resolution, device model, device manufacturer, network type, etc.
+ Application information: app ID, app name, app installation ID, app package name
+ Language settings, geographic location, UTM parameters, IP address, etc.

e.g. https://lp.pinduoduo.com/poros/h5 

The following shows the information collected by this ad library.

1. Collection of browser types

```js
var f = {
    MiniProgram: /miniprogram/i,
    WeChat: /MicroMessenger/i,
    QQ: /QQ\/[\d\.]+\s+/i,
    Baidu: /baidubrowser/i,
    Sogou: /sogoumobilebrowser/i,
    UC: /UCBrowser/i,
    QH: /qhbrowser/i,
    Chrome: /Chrome/i,
    Firefox: /Firefox/i,
    Safari: /Safari/i
};

function I(e) {
    return Object.keys(f).find(function(r) {
        return f[r].test(e);
    }) || "Unknown";
}
```

2. Collection of network types

```js
var p = {
    wifi: 1,
    "2g": 2,
    "3g": 3,
    "4g": 4
};

var w = navigator.connection && (navigator.connection.effectiveType || navigator.connection.type);
var networkType = p[w] || 0;
```

3. Collected Platform information

```js
function P() {
    var e = navigator.userAgent;
    var platform = {
        isAndroid: /Android/i.test(e),
        isIos: /iPhone|iPad|iPod/i.test(e),
        isMiniProgram: /miniprogram/i.test(e),
        isWeChat: /MicroMessenger/i.test(e),
        isQQ: /QQ\/[\d\.]+\s+/i.test(e),
        isWeibo: /Weibo/i.test(e),
        isTinyNativePlatform: /phh_android_version/i.test(e) || /phh_ios_version/i.test(e)
    };
    return platform;
}
```

4. Collected OS version information

```js
function J(e) {
    var platform = P();
    var version = '';
    if (platform.isAndroid) {
        version = (e.match(/Android (\d+).?(\d+)?/i) || [])[1] || '';
    } else if (platform.isIos) {
        version = (e.match(/os (\d+)_?(\d+)?/i) || [])[1] || '';
    }
    return version;
}
```

5. Fetched cookie, mainly focusing on the api_uid field

```js
function getCookies() {
    var cookie = document.cookie;
    var arr = cookie.split(";");
    var index;
    var cookieMap = {};
    for (var i = 0; i < arr.length; i++) {
        index = arr[i].indexOf("=");
        cookieMap[arr[i].slice(0, index).trim()] = arr[i].slice(index + 1).trim();
    }
    return {
        apiUid: cookieMap["api_uid"]
    };
}
```

6. The primary information collected includes, but is not limited to: city, province, device model, browser version, operating system version, device manufacturer, and various ID numbers

```js
var query = (window._parseQuery = parse)(window.location.search),
        ads_channel = query.ads_channel,
        cookieMap = getCookies(),
        apiUid = cookieMap.api_uid,
        city = "BeiJing",
        province = "BeiJing",
        modelByRiskControl = "Redmi K30 Pro",
        model = "redmi k30 pro",
        osVersion = "13",
        chromeVer = "124.0.6367.123",
        mftr = "xiaomi",
        clientTime = Date.now();

    var finalQueryStr = stringify(assign({
        api_uid: apiUid,
        client_time: clientTime
    }, query, {
        "second_material_id": "1",
        "jump_id": "1226",
        "ds_id1": "11",
        "abs_id": "165973",
        "template_id": "0",
        "style_id": "35913",
        "apk_id": "209",
        "city_lvl": "1",
        "city": city,
        "trigger_type": "4",
        "platform": "android",
        "model_by_risk_control": modelByRiskControl,
        "request_time": "1719321626192",
        "model_price": "2999",
        "province": province,
        "ads_rta_id": "12872",
        "chrome_ver": chromeVer,
        "model": model,
        "pdd_ads_pos": "INVENTORY_UNION_SLOT_REWARDED_VIDEO",
        "model_lvl": "3",
        "mftr": mftr,
        "lp_system_version": "13",
        "os_version": osVersion,
        "pdd_ads_csite": "900000001",
        "ads_set": "1802624705789956",
        "app_name": "unknown",
        "new_ads_csite": "INVENTORY_UNION_SLOT_REWARDED_VIDEO",
        "province_id": "2",
        "ads_id": "1802624651659332",
        "request_id": "2d2afff9c393479dae5cb8f4d175c4eb",
        "city_id": "52",
        "nsc_ver_type": "6",
        "page_goods_id": "438716630122",
        "act_cdc_id": "600216",
        "apk_ver_id": "8749",
        "nsc_cdc_id": "602835",
        "dnld_exc_id": "600009",
        "poros_sign": "3aaf4e3598d763875049fce5587587aa02cf336cedb2dc260f68a4b7f7591158a76e8c570a2c7c56f46127f4f7eb8045",
        "act_exc_id": "6000150000200063",
        "is_brn_city_excluded": "1",
        "apk_exc_id": "600932",
        "dnld_ver_id": "1071",
        "ply1": "788845",
        "is_enter_dnld": "0",
        "action_ver_type": "6",
        "act_ver_id": "22345",
        "new_ver_type": "6",
        "nsc_ver_id": "21172",
        "apk_cdc_id": "6",
        "ply6": "800164",
        "brn_ver_type": "1",
        "nsc_exc_id": "602095",
        "is_sc": "1",
        "sc_cate_id": "1",
        "dnld_cdc_id": "6",
        "render_mode": "rsc",
        "hash_token": "6a181104-3f43-4a98-a387-8fa45f716789",
        "launch_id": "6a181104-3f43-4a98-a387-8fa45f716789",
        "tmp_log_id": "6a181104-3f43-4a98-a387-8fa45f716789"
    }));
```

## Tag users of the same device with ads from the same ad libraries integrated in different APPs

### Saving fingerprint information in the Android file system

They can leverage Android's file system to aid in identification by storing the logo persistently or even writing it to a unified directory once the app has gained read/write access.  For example, in two different apk's, uni.UNI81E49D5 and com.qy.androidacts.topwidgets, there is the same third-party library, ksadsdk, and in the cache folder of the corresponding apps, there is a `ksadsdk/cookie` file with exactly the same contents.
 

<center>
    <img src="https://github.com/icespite/WTDetect/blob/main/images/image3.png?raw=true" style="zoom: 100%;" />
    <div><strong>Figure 3: The same cookie file in different apps.</strong></div>
    <br>
</center>


### Carrying fingerprint information in requests

We discovered some third-party libraries that carry the same parameters related to device information under different apps when requesting ad content. For example, in the third-party library openadsdk we found that when it communicates with `api.utofairy.com`, the same identifier `browser_identity` exists under different apps.

+ APP1：bzjh.three.com

<center>
    <img src="https://github.com/icespite/WTDetect/blob/main/images/bzjh.three.com.png?raw=true" style="zoom: 80%;" />
    <div><strong>Figure 4: The request from bzjh.three.com.</strong></div>
    <br>
</center>


+ APP2：com.bjt.qjh

<center>
    <img src="https://github.com/icespite/WTDetect/blob/main/images/com.bjt.qjh.png?raw=true" style="zoom: 80%;" />
    <div><strong>Figure 5: The request from com.bjt.qjh.</strong></div>
    <br>
</center>
 

+ APP3：com.black.taojujuvideo

<center>
    <img src="https://github.com/icespite/WTDetect/blob/main/images/com.black.taojujuvideo.png?raw=true" style="zoom: 80%;" />
    <div><strong>Figure 6: The request from com.black.taojujuvideo.</strong></div>
    <br>
</center>




# RQ4: The Necessity for Effective View Clicks (Review-B, C)
## Effective View Clicks is necessary
Different from web-based third-party tracking, the third-party tracking in an Android application is defined as giving a unique identifier for recognizing user by the third-party website which the third-party library loads. However, a web-based website can be accessed by inputting the domain name in a browser, while accessing third-party websites loaded by a third-party library is random. That’s to say, we must execute a series of operations to reach the target (a third-party website). For example, after executing OPERATION-1 in recognThings (com.mayt.recognThings.app), the target will be loaded from the third-party lib (com.bytedance.sdk.openadsdk). Furthermore, even when testing the same APP, the operations to load third-party website may be different. For instance, executing OPERATION-1 and OPERATION-2 in recognThings loads different target websites from ‘com.bytedance.sdk.openadsdk’ and ‘com.qq.e.ads’ respectively.

OPERATION-1: [Open APP, Upward]
OPERATION-2: [Open APP, Wait 5 seconds, Downward, Click ImageView]

In order to capture the source code of target websites on a large scale and build a dataset, we must design an automatic testing method instead of manual clicks. As a result, automatic GUI Testing Strategy is proposed, and the method of effective view clicking is one component of the strategy which is able to optimize the procedure of loading third-party websites.

In effective view clicking, ImageView, VideoView, and ViewFlipper, three elements that are more related to images and videos, are given higher click priority because they are more likely to come from a third-party library [4]. For example, the advertising lib ‘com.qq.e.ads’ always embeds an ImageView in the GUI for displaying ads and redirects users to third-party website after clicking the view. When the redirecting happens, WTDetect captures the source code of it and analyzes the tracking behavior.


## Why WTDetect is more efficient than MonkeyRunner?

We evaluated WTDetect and MonkeyRunner from two dimensions. The first dimension is the click-through rate for target views. We set ImageView, VideoView, and ViewFlipper as target views because they are highly related to advertisements. The first four columns of Table 1 show the effective click-through rate for each approach for the target views. Specifically, we calculated the number of clicks \( n \) and the number of clicks on the target views \( m \) for each approach, and then used \( m/n \) to represent the click-through rate for the target views. Effective Click indicates the number of clicks \( p \) that resulted in loading an advertisement, represented by \( p/n \). In this dimension, the higher the value, the more efficient the approach.

The last column shows the average time taken by each approach to successfully load 10 third-party websites with third-party libraries. In terms of average time, lower values indicate higher efficiency.

Analyzing the experimental results, we found that MonkeyRunner performs completely random click operations and cannot efficiently locate the positions of advertisements. On the other hand, MadDroid only improves the click-through rate for the first advertisement and does not consider subsequent actions such as closing the current advertisement and switching pages to find other advertisements. Furthermore, in actual tests, MonkeyRunner and MadDroid often perform poorly when dealing with difficult-to-exit advertisements (e.g., those that disable the back button). Our approach, however, considers and optimizes for these situations.

**Table 1: The click test coverage and efficiency result**

| Tool         | ImageView  | VideoView | ViewFlipper | Effective | Time/s    |
| ------------ | ---------- | --------- | ----------- | --------- | --------- |
| MonkeyRunner | 20.89%     | 0.57%     | 2.11%       | 2.04%     | 56.76     |
| MadDroid     | 30.56%     | 0.72%     | 5.52%       | 2.34%     | 39.39     |
| **WTDetect** | **38.47%** | **0.84%** | **7.43%**   | **3.03%** | **34.42** |


# RQ5: The Experiment Details and Data Analysis (Review-B, C)


## The Procedure of Dataset Labeling
The third-party tracking is defined as giving a unique identifier for different users or devices. As a result, we record the data from local storage APIs to label the experiment environment dataset. Notably, we constructed two datasets, WT^{exp} and WT^{truth}, in our study, the former consists of web-based third-party websites which are captured on desktop, while the latter is APP-based third-party websites that are captured on an Android device. WT^{exp} is used to train WTDetect and evaluate the performance of it. The trained WTDetect is used to detect the tracking behavior in WT^{truth} by running on the desktop, and the tracking patterns are given in Section 4.3. We don’t label WT^{truth} through this method because of the randomness of loading third-party websites in an Android APP. Executing the same operations in an APP may access different websites, for example, we executed OPERATION-1 twice in recognThings and accessed two different websites [5,6]. The randomness of accessing third-party websites makes it impossible to recognize whether the data of local storage APIs is unique.
Additionally, in the procedure of constructing WT^{truth}, we chose 64 APPs to capture the source code of target website. Firstly, we downloaded top-1k APPs from APPCHINA [7] and top-1k free APPs from Google Play [8]. We screened the APPs which contain advertising third-party libs by ANDetect [9], because they would load plenty of target websites for experiment samples. After manually checking the executability of APPs and the existence of third-party websites, 64 APPs remain.


## Reappearance of FP-INSPECTOR:
As a static-dynamic detecting tool for browser fingerprinting, FP-INSPECTOR solely detects the tracking behavior on Web-based websites. Given that WTDetect is essentially a static analysis tool, we reproduced the static analysis function of FP-INSPECTOR and compare it with WTDetect. Since [3] only open-sources the domain names of fingerprint-containing websites and potential fingerprinting APIs, we generated ASTs and extract static features according to the method provided in the paper, i.e. parent:child pairs that contain at least one keyword that matches a name, method, or property from one of the JavaScript APIs. Subsequently, the classification model was constructed using the decision tree given in the paper, trained and evaluated using the dataset WT^{exp} that we provide.

## FP&FN:
Although WTDetect is able to combat some code obfuscation, for example identifier renaming and dead code removal, it can’t recognize the tracking behavior of the source code using dynamic class loading, because WTDetect is essentially a static analysis tool. As a result, when the website uses API hiding, false negative happens. Additionally, when the website uses localstorage-based API to store application data, instead of tracking identifier, false positive happens. This is one of the technique challenges that we are currently unable to solve and will be optimized in future research.

## Data Analysis:
To more comprehensively assess the tracking behavior of Android third-party websites, WTDetect continuously examined a larger sample of websites, with WT^{truth} increasing from 302 to 587 (the number continues to grow), of which we analysed the proportion of tracking behaviors of different third-party repositories, as well as the most common storage-based and fingerprint-based tracking methods. There are 9 third-party libs with tracking behavior detected in 64 APPs. Notably, the tracking behavior is not being targeted to each APP, but to the third-party libs integrated in the APP, because the tracking website is loaded by the lib instead of the APP. Except for original third-party lib, WTDetect recognizes the domain name of every tracker and the data will be open-sourced in the future. The tracking behavior of different third-party libs on new dataset (WT^{truth}) is shown in Fig. 7. 

<center>
    <img src="https://github.com/icespite/WTDetect/blob/main/images/SDK_tracking.png?raw=true" style="zoom: 60%;" />
    <div><strong>Figure 7: The tracking behavior of different SDKs. None means no tracking. SB represents tracking solely through storage-based method, while BF represents tracking through browser fingerprinting. Both means existing storage-based tracking and browser fingerprinting simultaneously.</strong></div>
    <br>
</center>


Obviously, the websites loaded from ‘com.baidu.mobads’ favor to track users through the mix of storage-based methods and browser fingerprinting, while the websites loaded from ‘com.ironsource’ prefers using solely storage-based methods, like Cookies and localstorage. The tracking with only browser fingerprinting occurs in the websites loaded from ‘com.bytedance.openadsdk’, ‘com.mbridge.msdk’ and ‘com.applovin’. Across all 9 libs, the websites loaded by ‘com.bytedance.openadsdk’ have the least percentage of tracking behavior (7.00%), this might be linked to the strictness of the platform's review of the website's source code. As a advertising platform, ‘com.bytedance.openadsdk’ loads the advertisement websites which are placed by advertisers and reviews the website's source code. In conclusion, as traditional tracking methods, storage-based approaches are widely used in different third-party libs and browser fingerprinting does not usually appear alone, but together with storage-based approaches. On the new dataset, we count the most prevalent APIs used in browser fingerprinting and storage-based tracking separately, and the result is given in Tab. 2 and Tab. 3. The most common APIs that appear in the browser fingerprints of Android third-party websites are ‘userAgent’ and ‘platform’, which can distinguish between different browsers and Android devices. Cookies are still the most popular of the traditional tracking methods, offering better compatibility than localStorage and sessionStorage and providing flexible expiration times.


**Table 2: The frequency of browser fingerprinting APIs**
| Browser Fingerprinting API | count |
| -------------------------- | ----- |
| userAgent                  | 76    |
| platform                   | 74    |
| canvas                     | 49    |
| Color                      | 46    |
| language                   | 41    |


**Table 3: The frequency of storage-based tracking APIs**
| Storage-Based API | count |
| ------------------| ----- |
| Cookie            |91     |
| localStorage      |52     |
| sessionStorage    |16     |
| openDatabase      |2      |
| indexedDB	        |2      |


# RQ6: The Selection of PTG(Potential Tracking Graph) Features and Appropriate APIs  (Review-B, C)

## The Selection of PTG Features
On the basis of the original Table 6 in our paper, we add the column of Reference, which reflects the newly implemented features, and the literature we referred to select the existing features. The structure features and content features of PTG are shown in Tab. 4.


**Table 4: The structure features and content features of PTG**
|Feature Type|Feature Name|Description|Reference|
|-------|-------|-------|-------|
|Structure|Graph Size|The number of nodes, the number of edges, the ratio of nodes and edges, the number of subgraphs|[11]|
|Structure|Graph Density|The average density of all subgraphs|New|
|Structure|Average Connectivity|The average of the in-degree and out-degree of all nodes in the graph|New|
|Structure|Source and Sink Nodes|The number of all Source nodes and Sink nodes in the graph|New|
|Structure|Degree of Source Nodes|The average in-degree, average out-degree, average sum of in-degree and out-degree, and average connectivity of Source nodes|New|
|Structure|Degree of Sink Nodes|The average in-degree, average out-degree, average sum of in-degree and out-degree, and average connectivity of Sink nodes|New|
|Structure|Child Nodes of Source Nodes|The average number of child nodes of all Source nodes|New|
|Structure|Parent Nodes of Sink Nodes|The average number of parent nodes of all Sink nodes|New|
|Structure|Eccentricity of Source Nodes|The average eccentricity of Source nodes in the graph|New|
|Structure|Number of Source Nodes Owned by Sink Nodes|The maximum number of Source nodes owned by Sink nodes and the minimum number of Source nodes owned by Sink nodes in the graph|New|
|Structure|Connected Components|The number of nodes, the number of edges, and the ratio of nodes and edges of the maximal strongly connected subgraph|New|
|Content|Name of Source Nodes|The name of Source nodes represented in vector form|[3]|
|Content|Name of Sink Nodes|The name of Sink nodes represented in vector form|[3]|
|Content|Name of Child Nodes of Source Nodes|The concatenated name of child nodes of Source nodes represented in vector form|New|
|Content|Name of Child Nodes of Sink Nodes|The concatenated name of child nodes of Sink nodes represented in vector form|New|
|Content|Position of Source Nodes|The position and length of Source nodes and their child nodes in the code|[10]|
|Content|Position of Sink Nodes|The position and length of Sink nodes and their child nodes in the code|[10]|
|Content|Type of Source Nodes|Source nodes that read local caches are marked as 0, and other Source nodes are marked as 1|New|
|Content|Type of Sink Nodes|Sink nodes that write to local storage are marked as 0, and Sink nodes that transmit data over the network are marked as 1|New|


## The Selection of Appropriate APIs
After thoroughly researching the fingerprinting methods used in academia and industry, we have summarized 64 candidate features that can be used for fingerprint recognition. Based on the feature values corresponding to these features, and after dimensionality reduction through specific algorithms, a fingerprint corresponding to a browser instance is formed. The aforementioned candidate features are roughly divided into four categories: browser information, system information, hardware information, and Canvas fingerprint.

+ Browser information refers to the basic characteristics of the browser, encompassing fundamental parameters, user preference settings, and whether any anti-tracking measures are employed. Integrating these basic browser features as characteristics can reflect differences between browsers and the needs of different users for browser appearance and functionality.

+ System information refers to the system-level characteristics of the device on which the user's browser is running. Through browser APIs, information such as screen color depth, the number of installed fonts, platform information, and whether the system has been tampered with can be obtained. These features can be used to distinguish the systems on which different browser instances are running.

+ Device information pertains to each Android device's underlying hardware differences caused by varying manufacturing processes. Combining these differences can help distinguish between different Android devices.

+ Canvas fingerprinting utilizes the differences in graphics rendering by the browser to generate a unique fingerprint.

After selecting the aforementioned four categories comprising 64 features as candidate features for browser fingerprinting, data preprocessing is conducted to convert string-type features into numerical values. Finally, these features are screened using the Random Forest algorithm. A random selection of 200 samples from the dataset is used as the training set. To minimize the error caused by random sampling, the Random Forest algorithm is repeated 10 times to calculate the importance of each feature, and the mean importance is computed. The average importance measures of all features are shown in the figure below.

 
<center>
    <img src="https://github.com/icespite/WTDetect/blob/main/images/importance.png?raw=true" style="zoom: 100%;" />
    <div><strong>Figure 8: Importance of Fingerprint Attributes.</strong></div>
    <br>
</center>

Out of the total 64 features, 43.75% have an importance measure of 0. These features do not contribute to fingerprint generation and are genuinely redundant. Among these redundant features, sensor features and audio features each account for 28.57%. This is because browsers on Android devices generally do not support access to sensor information, technically limiting the ability to use sensor information as Android browser fingerprinting features. After dimensionality reduction, the number of features in the original candidate set was reduced from 64 to 36 features with an importance value greater than 0.

**Table 5: The information of Source API**
| Browser Fingerprinting Behavior |     Source API Class     |                Source API Attribute or Method                |
| :-----------------------------: | :----------------------: | :----------------------------------------------------------: |
|     **Browser Information**     |          Screen          |            height, width, availHeight, availWidth            |
|                                 |        navigator         | userAgent, language, productSub, languages, plugins, doNotTrack |
|                                 |           Date           |                      getTimezoneOffset                       |
|                                 |          window          |                     Intl.DateTimeFormat                      |
|                                 |         document         | body.addBehavior, body.appendChild, createElement, getElementsByClassName, removeChild |
|     **System Information**      |        navigator         |        platform, userAgent, oscup, vendor, vendorSub         |
|                                 |          window          |                    colorDepth, pixelDepth                    |
|    **Hardware Information**     |          window          | OfflineAudioContext, webkitOfflineAudioContext, DeviceLightEvent, DeviceProximityEvent, DeviceMotionEvent |
|                                 |        navigator         | hardwareConcurrency, cpuClass, deviceMemory, maxTouchPoints, geolocation, getUserMedia |
|                                 |         document         |            ontouchstart, createElement('canvas')             |
|                                 |          canvas          | getContext('webgl').getExtension('WEBGL_debug_renderer_info') |
|                                 |       AudioBuffer        |                          sampleRate                          |
|                                 |        AudioNode         | channelCount, numberOfInputs, numberOfOutputs, channelCountMode, channelInterpretation |
|     **Canvas Fingerprint**      |          THREE           |                     WebGLRenderer, Scene                     |
|                                 |         document         |        createElement('canvas'), createElement('img')         |
|                                 | CanvasRenderingContext2D |                     arc, fill, fillText                      |



# RQ7: The Details of Design Philosophy  (Review-C)
## Webpage Reconstruction

The purpose of reconstruction is to extract the source code of a webpage from a WebView. In the context of an app, there is no equivalent to the browser's F12 tool to save the source code. Therefore, we use Frida to hook into the WebView loading process to restore and save the source code. This means that dynamically loading content based on parameters does not affect our reconstruction process, as our goal is not to categorize webpage content.

We have compared the collected data and found that timestamps, random numbers, or differences generally appear in the URL parameters or are passed through different values via POST requests. In most cases, these differences do not cause significant changes to the file structure of the webpage; they only alter the values of certain variables in the file. We speculate that this is done to differentiate between users, so it typically does not affect our approach.

Of course, some SDKs use parameters like `pageid` to display different advertising content. We welcome changes in page content, as they correspond to different advertisements, which may lead to varying information collection behaviors. We treat each new page as new content. In practice, during our data collection process. We collect data from the same APP at different time periods and then remove identical webpages by calculating file hashes. We have also observed that some ad libraries show content strongly correlated with specific time points, suggesting that the ad library, upon recognizing the same device, only serves one advertisement within a certain period to increase the exposure rate of a single ad.

## The Strengths of Potential Tracking Graph
The essence of potential tracking graph generation is static analysis, which captures the website source code when loading resources, generates program dependence graph, and reflects taint propagation relationship on it. In contrast, dynamic analysis method hooks every relative API to recognize the tracking behavior [10], which greatly increases the time cost of detection. We hooked the APIs related to browser fingerprinting through OpenWPM to simulate the procedure of dynamic analysis and tested the executing time of the JavaScript files tested in Figure 5 in our paper. Shown in Fig. 9, it's clear that the execution time of the dynamic analysis is much longer than that of the static analysis.
 
 
<center>
    <img src="https://github.com/icespite/WTDetect/blob/main/images/execute_time.png?raw=true" style="zoom: 100%;" />
    <div><strong>Figure 9: The executing time between dynamic and static analysis. To simulate dynamic analysis, the procedure of hooking browser fingerprinting APIs is recorded. Accordingly, the process of potential tracking graph generation is tested.</strong></div>
    <br>
</center>

## Model Classification
In terms of model classification, we built two random forest models, one for identifying storage-based tracking and the other for identifying the existence of browser fingerprinting. The results calculated by Equation 1 in Section 3.4 will combine the results of the two models and give the final category.


# RQ8: Concern of the writing (Review-B, C)
Thank you for your comment, we will improve the writing and correct the formatting issues in our manuscript.



# References
[1] Eckersley, Peter. "How unique is your web browser?." Privacy Enhancing Technologies: 10th International Symposium, PETS 2010, Berlin, Germany, July 21-23, 2010. Proceedings 10. Springer Berlin Heidelberg, 2010.

[2] Yang, Zhiju, and Chuan Yue. "A comparative measurement study of web tracking on mobile and desktop environments." Proceedings on Privacy Enhancing Technologies 2020.2 (2020).

[3] Iqbal, Umar, Steven Englehardt, and Zubair Shafiq. "Fingerprinting the fingerprinters: Learning to detect browser fingerprinting behaviors." 2021 IEEE Symposium on Security and Privacy (SP). IEEE, 2021.

[4] Liu, Tianming, et al. "Maddroid: Characterizing and detecting devious ad contents for android apps." Proceedings of The Web Conference 2020. 2020.

[5] https://bit.ly/3YzKUq3

[6] https://bit.ly/3YvBls7

[7] http://m.appchina.com/

[8] https://play.google.com/store/games

[9] Xinyu, Liu, et al. "ANDetect: A Third-party Ad Network Libraries Detection Framework for Android Applications." Proceedings of the 39th Annual Computer Security Applications Conference. 2023.

[10] Su, Junhua, and Alexandros Kapravelos. "Automatic discovery of emerging browser fingerprinting techniques." Proceedings of the ACM Web Conference 2023. 2023.

[11] Iqbal, Umar, et al. "Adgraph: A graph-based approach to ad and tracker blocking." 2020 IEEE Symposium on security and privacy (SP). IEEE, 2020.